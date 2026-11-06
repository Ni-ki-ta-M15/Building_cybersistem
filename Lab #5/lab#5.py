import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import warnings
warnings.filterwarnings("ignore")


class DigitalEnvelope:
    def __init__(self):
        self.backend = default_backend()

    # ==========================================
    # ЧАСТИНА 1: АСИМЕТРИЧНА КРИПТОГРАФІЯ (RSA)
    # ==========================================

    def generate_rsa_keypair(self, private_key_file="private_key.pem", public_key_file="public_key.pem"):
        """Генерує пару ключів RSA (2048 біт) та зберігає їх у форматі PEM."""
        print("\n[*] Генерація ключової пари RSA (2048 біт)...")
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=self.backend
        )
        public_key = private_key.public_key()

        # Збереження закритого ключа (без пароля для спрощення демо)
        with open(private_key_file, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

        # Збереження відкритого ключа
        with open(public_key_file, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        print(f"[+] Ключі успішно збережено: '{private_key_file}' та '{public_key_file}'")

    def load_public_key(self, filename="public_key.pem"):
        with open(filename, "rb") as key_file:
            return serialization.load_pem_public_key(key_file.read(), backend=self.backend)

    def load_private_key(self, filename="private_key.pem"):
        with open(filename, "rb") as key_file:
            return serialization.load_pem_private_key(key_file.read(), password=None, backend=self.backend)

    # ==========================================
    # ЧАСТИНА 2: СИМЕТРИЧНА КРИПТОГРАФІЯ (AES) ТА КОНВЕРТ
    # ==========================================

    def encrypt_file_with_envelope(self, input_file, output_file, key_size, mode_name, public_key_file):
        """
        Генерує сеансовий ключ AES, шифрує ним файл, а сам ключ шифрує відкритим ключем RSA.
        """
        # 1. Генерація випадкового сеансового ключа AES та вектора ініціалізації (IV)
        aes_key = os.urandom(key_size // 8)
        iv = os.urandom(16)

        print(f"[*] Згенеровано сеансовий ключ AES ({key_size} біт) та IV (16 байт).")

        # 2. Налаштування шифрування AES
        if mode_name == 'CBC':
            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=self.backend)
        elif mode_name == 'CFB':
            cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=self.backend)
        else:
            raise ValueError("Невідомий режим шифрування")

        encryptor = cipher.encryptor()

        # 3. Читання файлу, вирівнювання (padding для CBC) та шифрування
        with open(input_file, "rb") as f:
            data = f.read()

        if mode_name == 'CBC':
            pad_length = 16 - (len(data) % 16)
            data += bytes([pad_length]) * pad_length

        ciphertext = encryptor.update(data) + encryptor.finalize()

        # 4. Шифрування сеансового ключа відкритим ключем RSA
        public_key = self.load_public_key(public_key_file)
        encrypted_aes_key = public_key.encrypt(
            aes_key,
            rsa_padding.OAEP(
                mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print("[*] Сеансовий ключ успішно зашифровано відкритим ключем RSA.")

        # 5. Збереження результату ("Цифрового конверта")
        # Формат: [Довжина зашифрованого ключа (4 байти)] + [Зашифрований ключ] + [IV (16 байт)] + [Шифротекст файлу]
        enc_key_len = len(encrypted_aes_key).to_bytes(4, byteorder='big')

        with open(output_file, "wb") as f:
            f.write(enc_key_len)
            f.write(encrypted_aes_key)
            f.write(iv)
            f.write(ciphertext)

        print(f"[+] Файл зашифровано та збережено як '{output_file}'")

    def decrypt_file_with_envelope(self, input_file, output_file, mode_name, private_key_file):
        """
        Витягує та розшифровує сеансовий ключ за допомогою закритого ключа RSA, а потім розшифровує файл.
        """
        # 1. Розбір "Цифрового конверта"
        with open(input_file, "rb") as f:
            enc_key_len = int.from_bytes(f.read(4), byteorder='big')
            encrypted_aes_key = f.read(enc_key_len)
            iv = f.read(16)
            ciphertext = f.read()

        # 2. Розшифрування сеансового ключа закритим ключем RSA
        print("[*] Відновлення сеансового ключа за допомогою закритого ключа RSA...")
        private_key = self.load_private_key(private_key_file)

        try:
            aes_key = private_key.decrypt(
                encrypted_aes_key,
                rsa_padding.OAEP(
                    mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            print("[+] Сеансовий ключ успішно відновлено!")
        except Exception as e:
            print("[-] ПОМИЛКА: Не вдалося відновити ключ. Можливо, використано неправильний закритий ключ.")
            return

        # 3. Дешифрування файлу алгоритмом AES
        if mode_name == 'CBC':
            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=self.backend)
        elif mode_name == 'CFB':
            cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=self.backend)

        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

        if mode_name == 'CBC':
            pad_length = decrypted_data[-1]
            decrypted_data = decrypted_data[:-pad_length]

        # 4. Збереження розшифрованого файлу
        with open(output_file, "wb") as f:
            f.write(decrypted_data)

        print(f"[+] Файл успішно розшифровано та збережено як '{output_file}'")


def main():
    envelope = DigitalEnvelope()

    while True:
        print("\n" + "=" * 65)
        print(" СИСТЕМА 'ЦИФРОВИЙ КОНВЕРТ' (AES + RSA OpenSSL)")
        print("=" * 65)
        print(" 1. Згенерувати ключі RSA (PEM)")
        print(" 2. Зашифрувати файл (Створити конверт)")
        print(" 3. Розшифрувати файл (Відкрити конверт)")
        print(" 0. Вийти")
        print("=" * 65)

        choice = input("Оберіть дію (0-3): ").strip()

        if choice == '0':
            print("Завершення роботи.")
            break

        elif choice == '1':
            envelope.generate_rsa_keypair()

        elif choice == '2':
            file_in = input("\nВведіть ім'я файлу для шифрування: ").strip()
            if not os.path.exists(file_in):
                print(f"[-] ПОМИЛКА: Файл '{file_in}' не знайдено!")
                continue

            print("\nОберіть довжину сеансового ключа AES:")
            print(" 1. AES-128 (16 байт)")
            print(" 2. AES-192 (24 байти)")
            print(" 3. AES-256 (32 байти)")
            k_choice = input("Ваш вибір (1-3): ").strip()
            key_sizes = {'1': 128, '2': 192, '3': 256}
            key_size = key_sizes.get(k_choice, 256)

            print("\nОберіть режим шифрування AES:")
            print(" 1. CBC (Cipher Block Chaining)")
            print(" 2. CFB (Cipher Feedback)")
            m_choice = input("Ваш вибір (1-2): ").strip()
            mode_name = 'CBC' if m_choice == '1' else 'CFB'

            file_out = file_in + ".enc"
            envelope.encrypt_file_with_envelope(file_in, file_out, key_size, mode_name, "public_key.pem")

        elif choice == '3':
            file_in = input("\nВведіть ім'я зашифрованого файлу (.enc): ").strip()
            if not os.path.exists(file_in):
                print(f"[-] ПОМИЛКА: Файл '{file_in}' не знайдено!")
                continue

            print("\nУ якому режимі AES був зашифрований файл?")
            print(" 1. CBC (Cipher Block Chaining)")
            print(" 2. CFB (Cipher Feedback)")
            m_choice = input("Ваш вибір (1-2): ").strip()
            mode_name = 'CBC' if m_choice == '1' else 'CFB'

            file_out = file_in.replace('.enc', '.dec')
            envelope.decrypt_file_with_envelope(file_in, file_out, mode_name, "private_key.pem")


if __name__ == "__main__":
    main()