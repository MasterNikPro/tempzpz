import os
import json
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

DATA_FILE = 'users.json'
TEMP_FILE = 'temp_users.json'

def load_users():
    try:
        with open(TEMP_FILE, 'r', encoding='latin-1') as file:
            data = file.read()
            if not data.strip():
                raise ValueError("Файл пустой или содержит только пробелы.")
            return json.loads(data)
    except FileNotFoundError:
        return {'ADMIN': {'password': 'admin', 'locked': False, 'restrictions': False}}
    except ValueError as e:
        print(f"Ошибка загрузки пользователей: {e}")
        return {'ADMIN': {'password': 'admin', 'locked': False, 'restrictions': False}}

def save_users(users):
    with open(TEMP_FILE, 'w', encoding='utf-8') as file:
        json.dump(users, file, indent=4)

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

def decrypt_data(encrypted_data, password):
    backend = default_backend()
    encrypted_data = base64.b64decode(encrypted_data)
    salt, iv, encrypted_data = encrypted_data[:16], encrypted_data[16:32], encrypted_data[32:]
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=backend
    )
    key = kdf.derive(password.encode())
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_data) + decryptor.finalize()

def validate_password(password, username, restrictions):
    if restrictions:
        has_latin = any(c.isalpha() and c.isascii() for c in password)
        has_cyrillic = any('а' <= c.lower() <= 'я' for c in password)
        has_digit = any(c.isdigit() for c in password)
        return has_latin, has_cyrillic, has_digit
    return True

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

def verify_signature(info, signature, public_key):
    try:
        public_key.verify(
            signature,
            info.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"Ошибка проверки подписи: {e}")
        return False

def admin_mode(users):
    while True:
        choice = input(
            "1. Змінити пароль\n2. Перегляд користувачів\n3. Додати користувача\n4. Блокування користувача\n5. Змінити обмеження пароля\n6. Вийти\nВаш вибір: ")
        if choice == '1':
            old_password = input("Введіть старий пароль: ")
            if users['ADMIN']['password'] == old_password:
                new_password = input("Введіть новий пароль: ")
                if validate_password(new_password, 'ADMIN', users['ADMIN']['restrictions']):
                    users['ADMIN']['password'] = new_password
                    save_users(users)
                    print("Пароль змінено.")
                else:
                    print("Невідповідність нового пароля обмеженням.")
            else:
                print("Неправильний пароль!")
        elif choice == '2':
            print("Список користувачів:")
            for username, info in users.items():
                print(f"{username}: {info}")
        elif choice == '3':
            new_user = input("Ім'я нового користувача: ")
            if new_user not in users:
                users[new_user] = {'password': '', 'locked': False, 'restrictions': False}
                save_users(users)
                print("Користувача додано.")
            else:
                print("Користувач вже існує.")
        elif choice == '4':
            username = input("Ім'я користувача для блокування: ")
            if username in users and username != 'ADMIN':
                users[username]['locked'] = True
                save_users(users)
                print("Користувача заблоковано.")
            else:
                print("Користувач не знайдений або неможливо заблокувати ADMIN.")
        elif choice == '5':
            username = input("Ім'я користувача для зміни обмежень: ")
            if username in users:
                users[username]['restrictions'] = not users[username]['restrictions']
                save_users(users)
                print(f"Обмеження {'включено' if users[username]['restrictions'] else 'виключено'}.")
            else:
                print("Користувач не знайдений.")
        elif choice == '6':
            break

def user_mode(user, users):
    while True:
        choice = input("1. Змінити пароль\n2. Вийти\nВаш вибір: ")
        if choice == '1':
            old_password = input("Введіть старий пароль: ")
            if users[user]['password'] == old_password:
                new_password = input("Введіть новий пароль: ")
                confirm_password = input("Підтвердіть новий пароль: ")
                if new_password == confirm_password and validate_password(new_password, user, users[user]['restrictions'] ):
                    users[user]['password'] = new_password
                    save_users(users)
                    print("Пароль успішно змінено.")
                else:
                    print("Пароль не відповідає обмеженням або підтвердження не співпадає.")
            else:
                print("Неправильний старий пароль!")
        elif choice == '2':
            break

def main():
    # Собираем информацию о компьютере
    try:
        computer_info = gather_computer_info()
        print(f"Информация о компьютере собрана: {computer_info}")
    except Exception as e:
        print(f"Ошибка сбора информации о компьютере: {e}")
        return

    # Хешируем информацию
    try:
        hashed_info = hash_info(computer_info)
        print(f"Информация захеширована: {hashed_info}")
    except Exception as e:
        print(f"Ошибка хеширования информации: {e}")
        return

    # Читаем подпись из реестра
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\Nikita_Zakharenko')
        signature, _ = winreg.QueryValueEx(key, 'Signature')
        encrypted_passphrase, _ = winreg.QueryValueEx(key, 'Passphrase')
        winreg.CloseKey(key)
        print("Подпись и парольная фраза успешно считаны из реестра.")
    except FileNotFoundError:
        print("Подпись или парольная фраза не найдены в реестре.")
        return
    except Exception as e:
        print(f"Ошибка при чтении из реестра: {e}")
        return

    # Загружаем публичный ключ
    try:
        with open('public_key.pem', 'rb') as f:
            public_key_pem = f.read()
        public_key = serialization.load_pem_public_key(public_key_pem)
        print("Публичный ключ успешно загружен.")
    except Exception as e:
        print(f"Ошибка загрузки публичного ключа: {e}")
        return

    # Проверяем подпись
    try:
        if not verify_signature(hashed_info, signature, public_key):
            print("Проверка подписи не пройдена. Работа программы завершена.")
            return
        print("Подпись успешно проверена.")
    except Exception as e:
        print(f"Ошибка проверки подписи: {e}")
        return

    # Запрашиваем парольную фразу для расшифровки файла с учетными данными
    try:
        master_key = 'some_master_key'
        passphrase = decrypt_data(encrypted_passphrase, master_key).decode('latin-1')
        print("Парольная фраза успешно расшифрована.")
    except Exception as e:
        print(f"Ошибка расшифровки парольной фразы: {e}")
        return

    # Расшифровываем файл с учетными данными
    try:
        with open(DATA_FILE, 'rb') as file:
            encrypted_data = file.read()
        decrypted_data = decrypt_data(encrypted_data, passphrase)
        with open(TEMP_FILE, 'wb') as temp_file:
            temp_file.write(decrypted_data)
        print("Файл с учетными данными успешно расшифрован.")
    except Exception as e:
        print(f"Ошибка при расшифровке файла: {e}")
        return

    # Проверяем содержимое расшифрованного файла
    try:
        with open(TEMP_FILE, 'r', encoding='latin-1') as file:
            data = file.read()
            if not data.strip():
                print("Внимание: файл с учетными данными пуст.")
            else:
                print(f"Содержимое расшифрованного файла: {data}")
    except Exception as e:
        print(f"Ошибка при чтении расшифрованного файла: {e}")
        return

    users = load_users()

    while True:
        username = input("Ім'я користувача (або 'вийти' для завершення): ")
        if username.lower() == 'вийти':
            break
        username = username.upper()
        if username in users:
            if users[username]['locked']:
                print("Обліковий запис заблокований.")
                continue
            password_attempts = 0
            while password_attempts < 3:
                password = input("Пароль: ")
                if users[username]['password'] == password:
                    if username == 'ADMIN':
                        admin_mode(users)
                    else:
                        user_mode(username, users)
                    break
                else:
                    print("Неправильний пароль. Спробуйте ще раз.")
                    password_attempts += 1
            if password_attempts == 3:
                print("Три невдалі спроби введення пароля. Програма завершує роботу.")
                break
        else:
            print("Користувач не знайдений. Спробуйте ще раз або зареєструйтеся як ADMIN.")

    # Шифруем файл с учетными данными перед выходом
    try:
        with open(TEMP_FILE, 'rb') as temp_file:
            data_to_encrypt = temp_file.read()
        encrypted_data = encrypt_data(data_to_encrypt, passphrase)
        with open(DATA_FILE, 'wb') as file:
            file.write(encrypted_data)
        os.remove(TEMP_FILE)
        print("Файл с учетными данными успешно зашифрован.")
    except Exception as e:
        print(f"Ошибка при шифровании файла: {e}")

if __name__ == '__main__':
    main()
