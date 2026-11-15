"""Recipe Box API — BE104 course skeleton.

A working Flask + SQLite CRUD API for recipes. It stores data perfectly —
and it trusts everyone. There is no authentication and no authorization yet.
That is the point: you will add both, lesson by lesson, in Units 2 and 3.
"""

import sqlite3

import jwt

import os

from datetime import datetime, timedelta, timezone

from dotenv import load_dotenv

from flask import Flask, g, jsonify, request

from auth_utils import hash_password, verify_password

load_dotenv()

DATABASE = "recipes.db"

app = Flask(__name__)

app.config["JWT_SECRET"] = os.environ.get("JWT_SECRET")

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def recipe_to_dict(row):
    return {
        "id": row["id"],
        "title": row["title"],
        "ingredients": row["ingredients"],
        "instructions": row["instructions"],
        "is_public": bool(row["is_public"]),
    }


@app.get("/")
def hello():
    return jsonify({"message": "Recipe Box API", "recipes": "/recipes"})

@app.post("/register")
def register():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "a JSON body is required"}), 400

    username = data.get("username")
    password = data.get("password")

    if not isinstance(username, str) or not username.strip():
        return jsonify({"error": "username is required"}), 400

    if not isinstance(password, str) or not password:
        return jsonify({"error": "password is required"}), 400

    
    username = username.strip()

    password_hash = hash_password(password)

    db = get_db()

    try:
        db.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, password_hash),
        )
        db.commit()
    except sqlite3.IntegrityError:
        db.rollback()
        return jsonify({"error": "username already exists"}), 409

    return jsonify({"message": "user registered successfully"}), 201



@app.post("/login")
def login():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "a JSON body is required"}), 400

    username = data.get("username")
    password = data.get("password")

    if not isinstance(username, str) or not username.strip() or not isinstance(password, str) or not password:
        return jsonify({"error": "username and password are required"}), 400

    db = get_db()
    user = db.execute(
    "SELECT id, username, password_hash, role FROM users WHERE username = ?",
    (username.strip(),)
    ).fetchone()

    if user is None or not verify_password(user["password_hash"], password):
        return jsonify({"error": "invalid username or password"}), 401

    token = jwt.encode(
    {
        "sub": str(user["id"]),
        "role": user["role"],  # <-- add this line
        "exp": datetime.now(timezone.utc) + timedelta(hours=1),
    },
    app.config["JWT_SECRET"],
    algorithm="HS256",
)

    return jsonify({
        "username": user["username"],
        "id": user["id"],
        "access_token": token,   # name is fine
    }), 200
  

@app.get("/recipes")
def list_recipes():
    rows = get_db().execute("SELECT * FROM recipes ORDER BY id").fetchall()
    return jsonify([recipe_to_dict(r) for r in rows])


@app.get("/recipes/<int:recipe_id>")
def get_recipe(recipe_id):
    row = get_db().execute(
        "SELECT * FROM recipes WHERE id = ?", (recipe_id,)
    ).fetchone()
    if row is None:
        return jsonify({"error": "recipe not found"}), 404
    return jsonify(recipe_to_dict(row))



def get_bearer_token():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None
    return auth_header.split(" ", 1)[1].strip()



@app.post("/recipes")
def create_recipe():
    token = get_bearer_token()

    if token is None:
        return jsonify({
            "error": "missing or invalid Authorization header"
        }), 401

    
    
    try:
        payload = jwt.decode(
            token,
            app.config["JWT_SECRET"],
            algorithms=["HS256"],
        )
        user_id = payload.get("sub")

    except jwt.ExpiredSignatureError:
        return jsonify({
            "error": "token has expired, please log in again"
        }), 401

    except jwt.PyJWTError:
        return jsonify({
            "error": "invalid token"
        }), 401

    data = request.get_json(silent=True)

    if not isinstance(data, dict) or not data.get("title") or not data.get("ingredients"):
        return jsonify({
            "error": "title and ingredients are required"
        }), 400



    
    db = get_db()
    try:
        cur = db.execute(
            "INSERT INTO recipes (title, ingredients, instructions, is_public, owner_id)"
            " VALUES (?, ?, ?, ?, ?)",
            (
                data["title"],
                data["ingredients"],
                data.get("instructions", ""),
                1 if data.get("is_public", True) else 0,
                user_id,
            ),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "a recipe with that title already exists"}), 409

    row = db.execute(
        "SELECT * FROM recipes WHERE id = ?", (cur.lastrowid,)
    ).fetchone()

    return jsonify(recipe_to_dict(row)), 201





@app.patch("/recipes/<int:recipe_id>")
def update_recipe(recipe_id):
    token = get_bearer_token()

    if token is None:
        return jsonify({
            "error": "missing or invalid Authorization header"
        }), 401

    try:
        payload = jwt.decode(
            token,
            app.config["JWT_SECRET"],
            algorithms=["HS256"],
        )
        user_id = int(payload["sub"])
        role = payload.get("role", "user")
    except (jwt.PyJWTError, KeyError, ValueError, TypeError):
        return jsonify({"error": "invalid or expired token"}), 401

    
    db = get_db()

    # Load the recipe to check ownership
    recipe = db.execute(
        "SELECT * FROM recipes WHERE id = ?",
        (recipe_id,)
    ).fetchone()

    if recipe is None:
        return jsonify({"error": "recipe not found"}), 404

    # Allow the recipe owner OR an admin to update
    is_owner = recipe["owner_id"] == user_id
    is_admin = role == "admin"

    if not (is_owner or is_admin):
        return jsonify({
            "error": "you do not have permission to modify this recipe"
        }), 403


    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "a JSON body is required"}), 400

    fields, values = [], []
    for column in ("title", "ingredients", "instructions"):
        if column in data:
            fields.append(f"{column} = ?")
            values.append(data[column])

    if "is_public" in data:
        fields.append("is_public = ?")
        values.append(1 if data["is_public"] else 0)

    if not fields:
        return jsonify({"error": "nothing to update"}), 400

    values.append(recipe_id)
    

    try:
        cur = db.execute(
            f"UPDATE recipes SET {', '.join(fields)} WHERE id = ?", values
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({
            "error": "a recipe with that title already exists"
        }), 409

    if cur.rowcount == 0:
        return jsonify({"error": "recipe not found"}), 404

    row = db.execute(
        "SELECT * FROM recipes WHERE id = ?", (recipe_id,)
    ).fetchone()

    return jsonify(recipe_to_dict(row))




@app.delete("/recipes/<int:recipe_id>")
def delete_recipe(recipe_id):
    token = get_bearer_token()

    if token is None:
        return jsonify({
            "error": "missing or invalid Authorization header"
        }), 401

    try:
        payload = jwt.decode(
            token,
            app.config["JWT_SECRET"],
            algorithms=["HS256"],
        )
        user_id = int(payload["sub"])
        role = payload.get("role", "user")
    except (jwt.PyJWTError, ValueError, TypeError):
        return jsonify({"error": "invalid or expired token"}), 401

    db = get_db()

    # Load the recipe before attempting to delete it
    recipe = db.execute(
        "SELECT * FROM recipes WHERE id = ?",
        (recipe_id,)
    ).fetchone()

    # Recipe doesn't exist
    if recipe is None:
        return jsonify({"error": "recipe not found"}), 404


    # Allow the recipe owner OR an admin to delete
    is_owner = recipe["owner_id"] == user_id
    is_admin = role == "admin"

    if not (is_owner or is_admin):
        return jsonify({
            "error": "you do not have permission to delete this recipe"
        }), 403

        # Permission verified: owner or admin may delete
    cur = db.execute(
        "DELETE FROM recipes WHERE id = ?",
        (recipe_id,)
    )
    db.commit()

    if cur.rowcount == 0:
        return jsonify({"error": "recipe not found"}), 404

    return "", 204




if __name__ == "__main__":
    app.run(debug=True, port=5001)

