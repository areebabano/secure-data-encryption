import hashlib, os, base64

def hash_passkey(passkey: str) -> str:
    """
    Generates a secure hashed representation of the provided passkey.

    The function creates a random 16-byte salt and uses PBKDF2 HMAC 
    with SHA-256 to derive a cryptographic key from the passkey.
    The result is base64-encoded for safe storage.

    Args:
        passkey (str): The plain text password to hash.

    Returns:
        str: A base64-encoded string containing the salt and the hashed key.
    """
    salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac("sha256", passkey.encode(), salt, 100_000)
    return base64.b64encode(salt + key).decode()

def check_passkey(input_passkey: str, stored_hash: str) -> str:
    """
    Verifies a provided passkey against a stored hash.

    Decodes the stored base64 hash to extract the salt and original key,
    then re-generates the key from the input passkey and compares them.

    Args:
        input_passkey (str): The password entered by the user.
        stored_hash (str): The base64-encoded string containing salt + stored key.

    Returns:
        bool: True if the passkey matches the stored hash, False otherwise.
    """
    decoded = base64.b64decode(stored_hash.encode())
    salt, stored_key = decoded[:16], decoded[16:]
    new_key = hashlib.pbkdf2_hmac("sha256", input_passkey.encode(), salt, 100_000)
    return new_key == stored_key

def authenticate_user(username, password, users):
    """
    Authenticates a user by validating the username and password.

    Args:
        username (str): The username to authenticate.
        password (str): The password provided by the user.
        users (dict): Dictionary containing user data.

    Returns:
        bool: True if authentication is successful, False otherwise.
    """
    if username not in users:
        return False
    return check_passkey(password, users[username]["password"])

def register_user(username, password, users):
    """
    Registers a new user by storing a hashed password.

    Args:
        username (str): The desired username.
        password (str): The password to be hashed and stored.
        users (dict): Dictionary containing user data.

    Returns:
        tuple: (bool, str) indicating success status and message.
    """
    if username in users:
        return False, "⚠️ Username already exists."
    users[username] = {
        "password": hash_passkey(password),
        "data": {}
    }
    return True, "✅ Registered successfully."