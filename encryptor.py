from cryptography.fernet import Fernet
import os
from dotenv import load_dotenv

# Step 1: Load environment variables from .env file
load_dotenv()

# Step 2: Fetch the Fernet key from the environment variable
fernet_key = os.getenv("FERNET_KEY")

# If fernet_key is not set in .env, raise an error
if fernet_key is None:
    raise ValueError("FERNET_KEY is not set in the environment variables.")

# 🛠️ Step 2: Create a Fernet object using the generated key
fernet = Fernet(fernet_key)

def encrypt_data(text: str) -> str:
    """
    Encrypts a string using Fernet symmetric encryption.

    Args:
        text (str): The plain text string that you want to encrypt.

    Returns:
        str: The encrypted version of the text, in string format.
    """
    # Step 3: Convert the text to bytes → Encrypt it → Convert back to string
    return fernet.encrypt(text.encode()).decode()

def decrypt_data(cipher_text: str) -> str:
    """
    Decrypts a previously encrypted string using Fernet.

    Args:
        cipher_text (str): The encrypted string you want to decrypt.

    Returns:
        str: The original plain text after decryption.
    """
    # Step 4: Convert encrypted string to bytes → Decrypt → Convert back to string
    return fernet.decrypt(cipher_text.encode()).decode()