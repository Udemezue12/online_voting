def validate_password(password):
    if not password:
        raise ValueError('Password cannot be empty or None')
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters")
