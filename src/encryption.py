"""Optional encryption for sensitive files at rest.

IMPORTANT: This is for DEVELOPMENT only. In production, use:
- Environment variables (no files)
- Secrets management services (AWS Secrets Manager, HashiCorp Vault, etc.)
- Kubernetes secrets
- Configuration manager services

This module provides Fernet (symmetric encryption) for encrypting .env files
if you must store them locally. The encryption password should be:
- Different from application secrets
- Stored securely (not in code)
- Rotated when access is revoked

Do NOT use this for production secrets.
"""

from pathlib import Path

try:
    import base64

    from cryptography.fernet import Fernet
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2

    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


def derive_key_from_password(password: str, salt: bytes = b"charlottesweb") -> bytes:
    """Derive encryption key from password using PBKDF2.

    Args:
        password: Master password for encryption
        salt: Salt for key derivation (fixed for consistency)

    Returns:
        Encryption key suitable for Fernet
    """
    if not CRYPTO_AVAILABLE:
        raise ImportError("cryptography library required for encryption. Install with: pip install cryptography")

    kdf = PBKDF2(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
        backend=default_backend(),
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key


def encrypt_env_file(
    input_path: str,
    output_path: str,
    password: str,
) -> None:
    """Encrypt a .env file.

    Args:
        input_path: Path to plaintext .env file
        output_path: Path to write encrypted file
        password: Master password for encryption

    Example:
        encrypt_env_file('.env', '.env.encrypted', password='my-master-password')
    """
    if not CRYPTO_AVAILABLE:
        raise ImportError("cryptography library required. Install with: pip install cryptography")

    # Read plaintext file
    input_file = Path(input_path)
    if not input_file.exists():
        raise FileNotFoundError(f".env file not found: {input_path}")

    plaintext = input_file.read_text()

    # Generate encryption key
    key = derive_key_from_password(password)
    cipher = Fernet(key)

    # Encrypt content
    encrypted = cipher.encrypt(plaintext.encode())

    # Write encrypted file
    output_file = Path(output_path)
    output_file.write_bytes(encrypted)

    print(f"✓ Encrypted {input_path} → {output_path}")
    print("⚠ Keep your master password safe - you'll need it to decrypt this file")


def decrypt_env_file(
    input_path: str,
    password: str,
) -> str:
    """Decrypt a .env file and return contents.

    Args:
        input_path: Path to encrypted .env file
        password: Master password for decryption

    Returns:
        Plaintext contents of .env file

    Example:
        env_content = decrypt_env_file('.env.encrypted', password='my-master-password')
    """
    if not CRYPTO_AVAILABLE:
        raise ImportError("cryptography library required. Install with: pip install cryptography")

    # Read encrypted file
    input_file = Path(input_path)
    if not input_file.exists():
        raise FileNotFoundError(f"Encrypted file not found: {input_path}")

    encrypted = input_file.read_bytes()

    # Generate encryption key
    key = derive_key_from_password(password)
    cipher = Fernet(key)

    # Decrypt content
    try:
        plaintext = cipher.decrypt(encrypted).decode()
        return plaintext
    except Exception as e:
        raise ValueError(f"Failed to decrypt file - wrong password? Error: {str(e)}")


def load_encrypted_env(
    file_path: str,
    password: str,
) -> dict[str, str]:
    """Load encrypted .env file into environment variables.

    Args:
        file_path: Path to encrypted .env file
        password: Master password for decryption

    Returns:
        Dictionary of environment variables

    Example:
        env_vars = load_encrypted_env('.env.encrypted', password='my-master-password')
        # Now set in os.environ as needed
        for key, value in env_vars.items():
            os.environ[key] = value
    """
    plaintext = decrypt_env_file(file_path, password)

    env_vars = {}
    for line in plaintext.splitlines():
        line = line.strip()

        # Skip empty lines and comments
        if not line or line.startswith("#"):
            continue

        # Parse KEY=VALUE
        if "=" in line:
            key, value = line.split("=", 1)
            env_vars[key.strip()] = value.strip()

    return env_vars


# CLI: Run this file directly to encrypt/decrypt
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage:")
        print("  python src/encryption.py encrypt <.env-file> <password>")
        print("  python src/encryption.py decrypt <.env.encrypted-file> <password>")
        sys.exit(1)

    action = sys.argv[1]

    if action == "encrypt" and len(sys.argv) >= 4:
        env_file = sys.argv[2]
        password = sys.argv[3]
        encrypt_env_file(env_file, f"{env_file}.encrypted", password)

    elif action == "decrypt" and len(sys.argv) >= 4:
        encrypted_file = sys.argv[2]
        password = sys.argv[3]
        try:
            content = decrypt_env_file(encrypted_file, password)
            print("Decrypted content:")
            print(content)
        except ValueError as e:
            print(f"✗ Decryption failed: {e}")
            sys.exit(1)

    else:
        print("Invalid arguments")
        sys.exit(1)
