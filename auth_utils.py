from werkzeug.security import generate_password_hash, check_password_hash


def hash_password(plain_password: str) -> str:
    """
    Take a plaintext password and return a secure hash.
    Never store or return the plaintext from this function.
    """
    return generate_password_hash(plain_password, method="pbkdf2:sha256")

def verify_password(stored_hash: str, candidate_password: str) -> bool:
    """
    Check whether a candidate password matches the stored hash.
    """
    return check_password_hash(stored_hash, candidate_password)