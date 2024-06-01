import os
import hashlib
import getpass
import platform
import winreg
import psutil
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64

def gather_computer_info():
    user_name = getpass.getuser()
    computer_name = platform.node()
    windows_folder = os.getenv('WINDIR')
    system_folder = os.getenv('SYSTEMROOT')
    disk_info = psutil.disk_usage('/')
    memory_size = disk_info.total

    info = f"{user_name}|{computer_name}|{windows_folder}|{system_folder}|{memory_size}"
    return info

def hash_info(info):
    return hashlib.sha256(info.encode()).hexdigest()

def generate_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

def sign_info(info, private_key):
    signature = private_key.sign(
        info.encode(),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    return signature

def write_to_registry(signature, encrypted_passphrase):
    try:
        key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, r'Software\Nikita_Zakharenko')
        winreg.SetValueEx(key, 'Signature', 0, winreg.REG_BINARY, signature)
        winreg.SetValueEx(key, 'Passphrase', 0, winreg.REG_BINARY, encrypted_passphrase)
        winreg.CloseKey(key)
        print("Підпис та парольна фраза успішно записані до реєстру.")
    except Exception as e:
        print(f"Помилка при запису до реєстру: {e}")

def encrypt_data(data, password):
    backend = default_backend()
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=backend
    )
    key = kdf.derive(password.encode())
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()
    return base64.b64encode(salt + iv + encrypted_data)

def main():
    try:
        install_path = input("Введіть папку для встановлення захищеної програми: ")
        os.makedirs(install_path, exist_ok=True)
        print(f"Папка '{install_path}' успішно створена.")
    except Exception as e:
        print(f"Помилка створення папки: {e}")
        return

    try:
        # Збираємо інформацію про комп'ютер
        computer_info = gather_computer_info()
        print(f"Інформацію про комп'ютер зібрано: {computer_info}")
    except Exception as e:
        print(f"Помилка збору інформації про комп'ютер: {e}")
        return

    try:
        # Хешуємо інформацію
        hashed_info = hash_info(computer_info)
        print(f"Інформацію захешовано: {hashed_info}")
    except Exception as e:
        print(f"Помилка хешування інформації: {e}")
        return

    try:
        # Генеруємо ключі
        private_key, public_key = generate_keys()
        print("Ключі успішно згенеровані.")
    except Exception as e:
        print(f"Помилка генерації ключів: {e}")
        return

    try:
        # Підписуємо інформацію
        signature = sign_info(hashed_info, private_key)
        print(f"Інформацію успішно підписано: {signature}")
    except Exception as e:
        print(f"Помилка підписання інформації: {e}")
        return

    try:
        # Зберігаємо публічний ключ для використання в захищеній програмі
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(os.path.join(install_path, 'public_key.pem'), 'wb') as f:
            f.write(public_key_pem)
        print("Публічний ключ успішно збережено.")
    except Exception as e:
        print(f"Помилка збереження публічного ключа: {e}")
        return

    try:
        # Запитуємо парольну фразу та зберігаємо її в реєстрі
        passphrase = input("Введіть парольну фразу для шифрування файлу з обліковими даними: ")
        encrypted_passphrase = encrypt_data(passphrase.encode(), 'some_master_key')
        print(f"Парольну фразу успішно зашифровано: {encrypted_passphrase}")
    except Exception as e:
        print(f"Помилка шифрування парольної фрази: {e}")
        return

    try:
        # Записуємо підпис та зашифровану парольну фразу до реєстру
        write_to_registry(signature, encrypted_passphrase)
    except Exception as e:
        print(f"Помилка запису до реєстру: {e}")

    print("Встановлення завершено.")

if __name__ == "__main__":
    main()
