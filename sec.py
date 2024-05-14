import os
import hashlib
import getpass
import platform
import winreg
import psutil
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization


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


def write_to_registry(signature):
    key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, r'Software\Student_Name')
    winreg.SetValueEx(key, 'Signature', 0, winreg.REG_BINARY, signature)
    winreg.CloseKey(key)


def main():
    install_path = input("Введите папку для установки защищаемой программы: ")
    os.makedirs(install_path, exist_ok=True)

    # Собираем информацию о компьютере
    computer_info = gather_computer_info()

    # Хешируем информацию
    hashed_info = hash_info(computer_info)

    # Генерируем ключи
    private_key, public_key = generate_keys()

    # Подписываем информацию
    signature = sign_info(hashed_info, private_key)

    # Записываем подпись в реестр
    write_to_registry(signature)

    # Сохраняем публичный ключ для использования в защищаемой программе
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(os.path.join(install_path, 'public_key.pem'), 'wb') as f:
        f.write(public_key_pem)

    print("Установка завершена.")


if __name__ == "__main__":
    main()
import os
import hashlib
import getpass
import platform
import winreg
import psutil
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization


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


def write_to_registry(signature):
    key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, r'Software\Student_Name')
    winreg.SetValueEx(key, 'Signature', 0, winreg.REG_BINARY, signature)
    winreg.CloseKey(key)


def main():
    install_path = input("Введите папку для установки защищаемой программы: ")
    os.makedirs(install_path, exist_ok=True)

    # Собираем информацию о компьютере
    computer_info = gather_computer_info()

    # Хешируем информацию
    hashed_info = hash_info(computer_info)

    # Генерируем ключи
    private_key, public_key = generate_keys()

    # Подписываем информацию
    signature = sign_info(hashed_info, private_key)

    # Записываем подпись в реестр
    write_to_registry(signature)

    # Сохраняем публичный ключ для использования в защищаемой программе
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(os.path.join(install_path, 'public_key.pem'), 'wb') as f:
        f.write(public_key_pem)

    print("Установка завершена.")


if __name__ == "__main__":
    main()
