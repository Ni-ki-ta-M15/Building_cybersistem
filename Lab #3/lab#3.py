import os
import time
import struct
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad


class ANSI_X917_Generator:
    """Генератор псевдовипадкових чисел за стандартом ANSI X9.17."""

    def __init__(self, key1: bytes, key2: bytes, seed: bytes):
        self._des3_key = key1 + key2
        self._cipher = DES3.new(self._des3_key, DES3.MODE_ECB)
        self._v = seed

    @staticmethod
    def _xor(b1: bytes, b2: bytes) -> bytes:
        return bytes(x ^ y for x, y in zip(b1, b2))

    def generate_session_key(self) -> bytes:
        # Ti: 64-бітне представлення поточного часу
        current_time = int(time.time() * 1000000)
        t_i = struct.pack('>Q', current_time & 0xFFFFFFFFFFFFFFFF)

        i_val = self._cipher.encrypt(t_i)
        r_i = self._cipher.encrypt(self._xor(i_val, self._v))
        self._v = self._cipher.encrypt(self._xor(i_val, r_i))

        return r_i


class KeyManager:
    """Модуль для захисту сеансового ключа за допомогою Майстер-ключа."""

    def __init__(self, master_key: bytes):
        self._master_key = master_key
        self._cipher = DES3.new(self._master_key, DES3.MODE_ECB)

    def protect_session_key(self, session_key: bytes) -> bytes:
        return self._cipher.encrypt(session_key)

    def recover_session_key(self, encrypted_session_key: bytes) -> bytes:
        return self._cipher.decrypt(encrypted_session_key)


def main():
    # Змінні для зберігання стану під час поточного сеансу
    session_key = None
    encrypted_session_key = None

    # Ініціалізація генератора та Майстер-ключа (вшитий у криптомодуль)
    gen_k1 = os.urandom(8)
    gen_k2 = os.urandom(8)
    seed = os.urandom(8)
    generator = ANSI_X917_Generator(gen_k1, gen_k2, seed)

    master_key = b'MasterKey_123456'  # 16 байт
    key_manager = KeyManager(master_key)

    while True:
        print("\n" + "=" * 65)
        print(" СИСТЕМА УПРАВЛІННЯ КРИПТОГРАФІЧНИМИ КЛЮЧАМИ (X9.17 + Envelope)")
        print("=" * 65)
        print(" 1. Згенерувати сеансовий ключ (ANSI X9.17)")
        print(" 2. Захистити сеансовий ключ (Схема з Майстер-ключем)")
        print(" 3. Зашифрувати повідомлення (збережеться у файл .enc)")
        print(" 4. Розшифрувати існуючий файл .enc (зчитає ключ із файлу)")
        print(" 0. Вийти")
        print("=" * 65)

        choice = input("Оберіть крок (0-4): ").strip()

        if choice == '1':
            print("\n--- КРОК 1: ГЕНЕРАЦІЯ КЛЮЧА ---")
            session_key = generator.generate_session_key()
            print(f"[+] УСПІХ! Сеансовий ключ згенеровано: {session_key.hex().upper()}")

        elif choice == '2':
            if not session_key:
                print("\n[-] ПОМИЛКА: Спочатку згенеруйте сеансовий ключ (Крок 1)!")
                continue

            print("\n--- КРОК 2: ЗАХИСТ СЕАНСОВОГО КЛЮЧА ---")
            encrypted_session_key = key_manager.protect_session_key(session_key)
            print(f"[+] УСПІХ! Ключ захищено Майстер-ключем.")
            print(f"    Зашифрований ключ EkM(ks): {encrypted_session_key.hex().upper()}")

        elif choice == '3':
            if not encrypted_session_key:
                print("\n[-] ПОМИЛКА: Спочатку захистіть сеансовий ключ (Крок 2)!")
                continue

            print("\n--- КРОК 3: ШИФРУВАННЯ ПОВІДОМЛЕННЯ ---")
            user_input = input("Введіть текст АБО ім'я файлу (наприклад, secret.txt): ").strip()

            output_enc_file = "message.enc"

            if not user_input:
                message = "Конфіденційні дані лабораторії"
                print(f"Використано повідомлення за замовчуванням: '{message}'")
            elif os.path.isfile(user_input):
                try:
                    with open(user_input, 'r', encoding='utf-8') as f:
                        message = f.read()
                    print(f"[+] Зчитано текст із файлу '{user_input}'")
                    output_enc_file = f"{user_input}.enc"
                except Exception as e:
                    print(f"[-] Помилка читання файлу: {e}")
                    continue
            else:
                message = user_input

            # Відновлюємо ключ і формуємо 16-байтний валідний ключ для 3DES
            recovered_key = key_manager.recover_session_key(encrypted_session_key)
            valid_3des_key = recovered_key + bytes(x ^ 0xFF for x in recovered_key)

            iv = b'InitVect'
            cipher_msg = DES3.new(valid_3des_key, DES3.MODE_CBC, iv=iv)
            encrypted_message = cipher_msg.encrypt(pad(message.encode('utf-8'), DES3.block_size))

            # АРХІТЕКТУРА ENVELOPE: Записуємо спочатку 8 байт зашифрованого ключа, а потім повідомлення
            try:
                with open(output_enc_file, 'wb') as f:
                    f.write(encrypted_session_key)  # 8 байт
                    f.write(encrypted_message)  # Решта - текст

                print(f"\n[+] УСПІХ! Дані ЗБЕРЕЖЕНО у файл: {output_enc_file}")
                print("    (Зашифрований сеансовий ключ прикріплено до початку файлу)")
            except Exception as e:
                print(f"[-] Помилка запису файлу: {e}")

        elif choice == '4':
            print("\n--- КРОК 4: РОЗШИФРУВАННЯ ФАЙЛУ ---")
            file_to_decrypt = input("Введіть ім'я .enc файлу (наприклад, secret.txt.enc): ").strip()

            if not os.path.exists(file_to_decrypt):
                print(f"[-] ПОМИЛКА: Файл '{file_to_decrypt}' не знайдено!")
                continue

            try:
                with open(file_to_decrypt, 'rb') as f:
                    # Читаємо перші 8 байт — це наш зашифрований сеансовий ключ
                    file_enc_session_key = f.read(8)
                    # Читаємо все інше — це зашифрований текст
                    encrypted_data = f.read()
            except Exception as e:
                print(f"[-] Помилка читання файлу: {e}")
                continue

            # Відновлюємо сеансовий ключ за допомогою Майстер-ключа
            try:
                recovered_key = key_manager.recover_session_key(file_enc_session_key)
                valid_3des_key = recovered_key + bytes(x ^ 0xFF for x in recovered_key)

                iv = b'InitVect'
                cipher_msg_dec = DES3.new(valid_3des_key, DES3.MODE_CBC, iv=iv)
                decrypted_msg = unpad(cipher_msg_dec.decrypt(encrypted_data), DES3.block_size).decode('utf-8')

                output_dec_file = file_to_decrypt.replace('.enc', '.dec')
                with open(output_dec_file, 'w', encoding='utf-8') as f:
                    f.write(decrypted_msg)

                print(f"\n[+] УСПІХ! Дані успішно розшифровано та ЗБЕРЕЖЕНО у файл: {output_dec_file}")
                print(f"    Відновлений текст:\n\n{decrypted_msg}\n")
            except Exception as e:
                print(f"[-] Помилка розшифрування: Можливо дані або ключ пошкоджено. ({e})")

        elif choice == '0':
            print("\nЗавершення роботи. До побачення!")
            break
        else:
            print("\n[-] Невірний вибір. Введіть цифру від 0 до 4.")


if __name__ == "__main__":
    main()