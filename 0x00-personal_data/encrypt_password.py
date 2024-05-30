#!/usr/bin/env python3
""" Defines a hash_password function to return a hashed password """
import bcrypt


def hash_password(password: str) -> bytes:
    """Hashes a password using bcrypt and returns the salted, hashed password."""
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode(), salt)
    return hashed_password


def is_valid(hashed_password: bytes, password: str) -> bool:
    """Validates that the provided password matches the hashed password."""
    return bcrypt.checkpw(password.encode(), hashed_password)
