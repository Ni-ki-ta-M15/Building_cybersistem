import os
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


class ModernCryptoSystem:
    def __init__(self):
        self.ZERO_IV = bytes([0] * 16)  # Нульовий вектор ініціалізації (вимога методички)

    def generate_key_from_password(self, password: str, key_size: int) -> bytes:
        """
        Генерує сеансовий ключ на основі пароля за допомогою SHA-256.
        key_size вказується в бітах (128, 192 або 256).
        """
        # Хешуємо пароль через SHA-256
        hashed_password = hashlib.sha256(password.encode('utf-8')).digest()

        # Обрізаємо хеш до потрібної довжини ключа (в байтах)
        bytes_needed = key_size // 8
        return hashed_password[:bytes_needed]

    def process_file(self, input_file: str, output_file: str, password: str,
                     key_size: int, mode_name: str, encrypt: bool):
        """Шифрує або дешифрує файл."""
        # 1. Отримуємо ключ потрібної довжини
        key = self.generate_key_from_password(password, key_size)

        # 2. Налаштовуємо режим шифрування
        if mode_name == 'ECB':
            cipher = AES.new(key, AES.MODE_ECB)
        elif mode_name == 'CBC':
            cipher = AES.new(key, AES.MODE_CBC, iv=self.ZERO_IV)
        elif mode_name == 'CFB':
            # Для CFB використовуємо сегмент розміром 128 біт
            cipher = AES.new(key, AES.MODE_CFB, iv=self.ZERO_IV, segment_size=128)
        else:
            raise ValueError("Невідомий режим шифрування")

        # 3. Читаємо файл
        with open(input_file, 'rb') as f:
            data = f.read()

        # 4. Виконуємо криптографічне перетворення
        if encrypt:
            # Для ECB та CBC потрібен padding (вирівнювання блоків), CFB працює як потоковий
            if mode_name in ['ECB', 'CBC']:
                data = pad(data, AES.block_size)
            result_data = cipher.encrypt(data)
        else:
            result_data = cipher.decrypt(data)
            if mode_name in ['ECB', 'CBC']:
                result_data = unpad(result_data, AES.block_size)

        # 5. Записуємо результат
        with open(output_file, 'wb') as f:
            f.write(result_data)


def main():
    crypto = ModernCryptoSystem()

    while True:
        print("\n" + "=" * 65)
        print(" СИМЕТРИЧНЕ ШИФРУВАННЯ ДАНИХ (AES + SHA-256)")
        print(" Аналог CryptoAPI / CNG (Кросплатформенна реалізація)")
        print("=" * 65)
        print(" 1. Зашифрувати файл")
        print(" 2. Розшифрувати файл")
        print(" 0. Вийти")
        print("=" * 65)

        choice = input("Оберіть дію (0-2): ").strip()

        if choice == '0':
            print("Завершення роботи.")
            break

        if choice in ['1', '2']:
            is_encrypt = (choice == '1')
            action_name = "Шифрування" if is_encrypt else "Дешифрування"

            # Запит параметрів у користувача
            file_in = input(f"Введіть ім'я файлу для {action_name.lower()}: ").strip()
            if not os.path.exists(file_in):
                print(f"[-] ПОМИЛКА: Файл '{file_in}' не знайдено!")
                continue

            password = input("Введіть пароль: ").strip()

            print("\nОберіть довжину ключа AES:")
            print(" 1. AES-128 (16 байт)")
            print(" 2. AES-192 (24 байти)")
            print(" 3. AES-256 (32 байти)")
            key_choice = input("Ваш вибір (1-3): ").strip()
            key_sizes = {'1': 128, '2': 192, '3': 256}
            key_size = key_sizes.get(key_choice, 128)  # За замовчуванням 128

            print("\nОберіть режим шифрування:")
            print(" 1. ECB (Electronic Codebook)")
            print(" 2. CBC (Cipher Block Chaining - з нульовим IV)")
            print(" 3. CFB (Cipher Feedback - з нульовим IV)")
            mode_choice = input("Ваш вибір (1-3): ").strip()
            modes = {'1': 'ECB', '2': 'CBC', '3': 'CFB'}
            mode_name = modes.get(mode_choice, 'CBC')  # За замовчуванням CBC

            # Формування імені вихідного файлу
            if is_encrypt:
                file_out = file_in + ".enc"
            else:
                file_out = file_in.replace('.enc', '.dec') if '.enc' in file_in else file_in + ".dec"

            # Виконання операції
            try:
                crypto.process_file(file_in, file_out, password, key_size, mode_name, encrypt=is_encrypt)
                print(f"\n[+] УСПІХ! Операція '{action_name}' виконана.")
                print(f"    AES-{key_size} (Режим: {mode_name}).")
                print(f"    Ключ згенеровано з пароля за допомогою SHA-256.")
                print(f"    Результат збережено у файл: {file_out}")
            except ValueError as e:
                print(f"\n[-] ПОМИЛКА розшифрування: Можливо, невірний пароль, режим або розмір ключа. ({e})")
            except Exception as e:
                print(f"\n[-] СИСТЕМНА ПОМИЛКА: {e}")


if __name__ == "__main__":
    main()