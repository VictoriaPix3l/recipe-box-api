# Security Baseline – Open Recipe API

Date: 2026-11-06 (local time)

## Anonymous Read
- Request: `GET /recipes`
- Status: `200 OK`
- Outcome: Returned recipes without authentication, including a private recipe: `{"id":3,"title":"Secret family hot sauce","is_public":false}`.

## Anonymous Create
- Request: `POST /recipes`
- Status: `201 Created`
- Outcome: Created temporary test recipe ID 4 without authentication.

## Anonymous Update
- Request: `PATCH /recipes/3`
- Body: `{"title":"Totally not secret anymore hot sauce"}`
- Status: `200 OK`
- Outcome: `GET /recipes/3` returned `200 OK` and confirmed the updated title persisted without authentication.

## Anonymous Delete
- Request: `DELETE /recipes/4`
- Status: `204 No Content`
- Outcome: A follow-up `GET /recipes/4` returned `404 Not Found` with `{"error":"recipe not found"}`. No authentication was required.

## Summary
The local Recipe Box API allows anonymous users to read, create, update, and delete recipes. A recipe marked `is_public: false` was readable and editable without authentication. These are baseline security findings; no fixes have been applied yet.