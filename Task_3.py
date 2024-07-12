from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import hashlib
import os


def load_and_process_jpeg(file_path):
    try:
        with open(file_path, 'rb') as file:
            content = file.read()
        end_marker = content.find(b'\xff\xd9')
        if end_marker != -1:
            return content[:end_marker + 2], content[end_marker + 2:]
        return content, b''
    except FileNotFoundError:
        print("Файл не найден")
        return None, None
    except Exception as e:
        print(f"Ошибка при чтении файла: {e}")
        return None, None


def create_cipher(iv, key):
    return Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())


def decrypt_data(cipher, data):
    decryptor = cipher.decryptor()
    return decryptor.update(data) + decryptor.finalize()


def main():
    file_path = 'I2.jpg'
    if not os.path.exists(file_path):
        print("Файл не найден")
        return

    clean_data, encrypted_data = load_and_process_jpeg(file_path)
    if clean_data is None or encrypted_data is None:
        return

    md5_hasher = hashlib.md5()
    md5_hasher.update(clean_data)
    encryption_key = md5_hasher.digest()

    iv_hex = 'e502d2fdc8b66ed61398a25623003cf4'
    iv = bytes.fromhex(iv_hex)

    encrypted_data = encrypted_data[:16]

    cipher = create_cipher(iv, encryption_key)
    decrypted_data = decrypt_data(cipher, encrypted_data)

    try:
        decrypted_text = decrypted_data.decode('utf-8')
    except UnicodeDecodeError:
        print("Ошибка декодирования данных")
        return

    print(f"Расшифрованный текст: {decrypted_text}")


if __name__ == "__main__":
    main()
