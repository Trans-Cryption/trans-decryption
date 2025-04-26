import json
import base64
import argparse
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

debug = False


def fix_base64_padding(data):
    """Add padding to base64 string if needed"""
    padding_needed = len(data) % 4
    if padding_needed:
        return data + "=" * (4 - padding_needed)
    return data


def read_file_content(file_path):
    """Read file content, handling both direct content and file paths"""
    if os.path.exists(file_path):
        with open(file_path, "r") as f:
            return f.read().strip()
    return file_path.strip()


def decrypt_aes_cryptojs_format(encrypted_data, key):
    """
    Decrypt data encrypted with CryptoJS AES encryption format
    CryptoJS uses a specific format: salt + iv + ciphertext
    """
    try:
        # Decode the base64 data
        data = base64.b64decode(encrypted_data)

        # CryptoJS format starts with "Salted__" followed by 8 bytes of salt
        if data[:8] != b"Salted__":
            raise ValueError("Invalid CryptoJS format")

        salt = data[8:16]
        ciphertext = data[16:]

        # CryptoJS derives key and IV using OpenSSL's EVP_BytesToKey
        # We'll implement a simplified version
        derived = evp_bytes_to_key(key, salt)
        key_derived = derived[:32]  # AES-256 key
        iv = derived[32:48]  # 16 bytes IV

        # Decrypt
        cipher = Cipher(
            algorithms.AES(key_derived), modes.CBC(iv), backend=default_backend()
        )
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ciphertext) + decryptor.finalize()

        # Remove PKCS#7 padding
        padding_length = decrypted[-1]
        return decrypted[:-padding_length].decode("utf-8")
    except Exception as e:
        print(f"Error in AES decryption: {e}")
        raise


def evp_bytes_to_key(key, salt, key_size=32, iv_size=16):
    """
    OpenSSL's EVP_BytesToKey key derivation function
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend

    key_bytes = key.encode("utf-8") if isinstance(key, str) else key
    d = b""
    current_hash = b""
    while len(d) < key_size + iv_size:
        md5 = hashes.Hash(hashes.MD5(), backend=default_backend())
        if current_hash:
            md5.update(current_hash)
        md5.update(key_bytes)
        md5.update(salt)
        current_hash = md5.finalize()
        d += current_hash
    return d[: key_size + iv_size]


def decrypt_message(encrypted_data, encrypted_key, private_key_path):
    try:
        # Read file contents if they're file paths
        encrypted_data_content = read_file_content(encrypted_data)
        encrypted_key_content = read_file_content(encrypted_key)

        # Fix padding if needed
        encrypted_data_content = fix_base64_padding(encrypted_data_content)
        encrypted_key_content = fix_base64_padding(encrypted_key_content)

        if debug:
            print(f"[DEBUG] Encrypted data length: {len(encrypted_data_content)}")
            print(f"[DEBUG] Encrypted key length: {len(encrypted_key_content)}")

        # Load the private key
        with open(private_key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(), password=None, backend=default_backend()
            )

        # Debug the key content before decoding
        try:
            if debug:
                print(
                    f"[DEBUG] First 10 chars of encrypted key: {encrypted_key_content[:10]}..."
                )
            # Decode base64 encrypted key
            encrypted_key_bytes = base64.b64decode(encrypted_key_content)

            if debug:
                print(f"[DEBUG] Successfully decoded key from base64")
        except Exception as e:
            print(f"[ERROR] Failed to decode key: {e}")
            # Try to fix common encoding issues
            if debug:
                print("[DEBUG] Attempting to fix encoding issues...")
            encrypted_key_content = (
                encrypted_key_content.replace("\n", "")
                .replace("\r", "")
                .replace(" ", "+")
            )
            encrypted_key_bytes = base64.b64decode(
                fix_base64_padding(encrypted_key_content)
            )
            if debug:
                print(f"[DEBUG] Fixed and decoded key successfully")

        # Decrypt the AES key with RSA
        try:
            aes_key = private_key.decrypt(
                encrypted_key_bytes,
                padding.PKCS1v15(),
            ).decode("utf-8")
            if debug:
                print(f"[DEBUG] Successfully decrypted AES key")
        except Exception as e:
            if debug:
                print(f"[ERROR] Failed to decrypt AES key: {e}")
            raise

        # Decrypt the data with the AES key
        try:
            decrypted_data = decrypt_aes_cryptojs_format(
                encrypted_data_content, aes_key
            )
            return decrypted_data
        except Exception as e:
            print(f"[ERROR] Failed to decrypt data: {e}")
            return None

    except Exception as main_error:
        print(f"[CRITICAL ERROR] {main_error}")
        return None


def main():
    parser = argparse.ArgumentParser(
        description="Decrypt form data from encrypted web3forms submissions"
    )
    parser.add_argument(
        "--data", required=True, help="Encrypted data string or file path"
    )
    parser.add_argument(
        "--key", required=True, help="Encrypted AES key string or file path"
    )
    parser.add_argument(
        "--private-key", required=True, help="Path to RSA private key file"
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")

    args = parser.parse_args()

    global debug
    debug = args.debug

    if debug:
        print("[DEBUG] Starting decryption process...")

    decrypted = decrypt_message(args.data, args.key, args.private_key)
    if decrypted:
        try:
            # Try to parse as JSON
            data = json.loads(decrypted)
            print("Decrypted form data:")
            for key, value in data.items():
                print(f"{key}: {value}")
        except json.JSONDecodeError:
            # If not valid JSON, print as plain text
            print("Decrypted content (non-JSON):")
            print(decrypted)
    else:
        print("Failed to decrypt message")


if __name__ == "__main__":
    main()
