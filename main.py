import json

DATA_FILE = 'users.json'
def load_users():
    try:
        with open(DATA_FILE, 'r') as file:
            return json.load(file)
    except FileNotFoundError:

        return {'ADMIN': {'password': 'admin', 'locked': False, 'restrictions': False}}
def save_users(users):
    with open(DATA_FILE, 'w') as file:
        json.dump(users, file, indent=4)

def validate_password(password, username, restrictions):
    if restrictions:
        has_latin = any(c.isalpha() and c.isascii() for c in password)
        has_cyrillic = any('а' <= c.lower() <= 'я' for c in password)
        has_digit = any(c.isdigit() for c in password)
        return has_latin and has_cyrillic and has_digit
    return True
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
                if new_password == confirm_password and validate_password(new_password, user,
                                                                          users[user]['restrictions']):
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


if __name__ == '__main__':
    main()
