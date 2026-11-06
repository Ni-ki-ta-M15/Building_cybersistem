import struct
import os

# --- ANSI Кольори для консолі ---
C_CYAN = '\033[96m'
C_GREEN = '\033[92m'
C_YELLOW = '\033[93m'
C_RED = '\033[91m'
C_RESET = '\033[0m'
C_BOLD = '\033[1m'

# 1. Таблиця замін (S-блоки)
S_BOX = [
    [4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3],
    [14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9],
    [5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11],
    [7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3],
    [6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2],
    [4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14],
    [13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12],
    [1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12]
]


def rol11(x):
    return ((x << 11) & 0xFFFFFFFF) | (x >> 21)


def f32(x, k):
    s = (x + k) % (1 << 32)
    res = 0
    for i in range(8):
        part = (s >> (4 * i)) & 0x0F
        res |= (S_BOX[i][part] << (4 * i))
    return rol11(res)


def encrypt_block(block, key):
    n1, n2 = struct.unpack('<LL', block)
    keys = struct.unpack('<8L', key)
    for i in range(24):
        n1, n2 = n2, n1 ^ f32(n2, keys[i % 8])
    for i in range(8):
        n1, n2 = n2, n1 ^ f32(n2, keys[7 - i])
    return struct.pack('<LL', n2, n1)


def decrypt_block(block, key):
    n1, n2 = struct.unpack('<LL', block)
    keys = struct.unpack('<8L', key)
    for i in range(8):
        n1, n2 = n2, n1 ^ f32(n2, keys[i])
    for i in range(24):
        n1, n2 = n2, n1 ^ f32(n2, keys[7 - (i % 8)])
    return struct.pack('<LL', n2, n1)


def pad(data):
    pad_len = 8 - (len(data) % 8)
    return data + bytes([pad_len] * pad_len)


def unpad(data):
    return data[:-data[-1]]


def process_data(data, key, iv, mode, is_encrypt):
    if mode == 'ECB':
        if is_encrypt: data = pad(data)
        res = bytearray()
        for i in range(0, len(data), 8):
            block = data[i:i + 8]
            res += encrypt_block(block, key) if is_encrypt else decrypt_block(block, key)
        if not is_encrypt: res = unpad(res)
        return res

    elif mode == 'CTR':
        res = bytearray()
        counter = int.from_bytes(iv, 'little')
        for i in range(0, len(data), 8):
            block = data[i:i + 8]
            gamma = encrypt_block(counter.to_bytes(8, 'little'), key)
            res += bytes(a ^ b for a, b in zip(block, gamma[:len(block)]))
            counter += 1
        return res

    elif mode == 'CFB':
        res = bytearray()
        if is_encrypt: data = pad(data)
        prev = iv
        for i in range(0, len(data), 8):
            block = data[i:i + 8]
            gamma = encrypt_block(prev, key)
            if is_encrypt:
                cipher_block = bytes(a ^ b for a, b in zip(block, gamma))
                res += cipher_block
                prev = cipher_block
            else:
                plain_block = bytes(a ^ b for a, b in zip(block, gamma))
                res += plain_block
                prev = block
        if not is_encrypt: res = unpad(res)
        return res


def get_files():
    return [f for f in os.listdir('') if os.path.isfile(f) and not f.endswith('.py') and not f.startswith('.')]


if __name__ == "__main__":
    while True:
        print(f"\n{C_CYAN}{'=' * 60}{C_RESET}")
        print(f"{C_BOLD}Шифратор ГОСТ 28147:2009 | Головне меню{C_RESET}")
        print(f"{C_CYAN}{'=' * 60}{C_RESET}")

        files = get_files()

        if not files:
            print(f"{C_YELLOW}[!] Файлів не знайдено. Створюємо тестовий файл 'secret.txt'...{C_RESET}")
            with open("../Lab #3/secret.txt", "w", encoding="utf-8") as f:
                f.write("Це секретне повідомлення для перевірки алгоритму ГОСТ 28147:2009!")
            files = ["secret.txt"]

        print(f"{C_BOLD}Доступні файли:{C_RESET}")
        for idx, f in enumerate(files):
            if f.endswith('.enc'):
                color, status = C_RED, "(Зашифрований)"
            elif f.endswith('.dec'):
                color, status = C_GREEN, "(Розшифрований)"
            else:
                color, status = C_YELLOW, "(Оригінал)"
            print(f"  {C_CYAN}[{idx + 1}]{C_RESET} {color}{f} {status}{C_RESET}")

        print(f"  {C_CYAN}[0]{C_RESET} {C_BOLD}Вийти з програми{C_RESET}")

        choice = input(f"\nОберіть номер файлу (або 0 для виходу): ").strip()

        if choice == '0':
            print(f"{C_GREEN}Роботу завершено. До побачення!{C_RESET}")
            break

        if not choice.isdigit() or int(choice) < 1 or int(choice) > len(files):
            print(f"{C_RED}[-] Невірний вибір.{C_RESET}")
            continue

        in_file = files[int(choice) - 1]
        is_enc_file = in_file.endswith('.enc')

        # --- ЗАПИТ ДІЇ ТА РЕЖИМУ ---
        action_text = "Дешифрувати" if is_enc_file else "Зашифрувати"
        action = input(f"\nОберіть дію (1 - Зашифрувати, 2 - Дешифрувати) [Enter = {action_text}]: ").strip()
        if not action: action = '2' if is_enc_file else '1'
        is_encrypt = True if action == '1' else False

        print(f"\n{C_CYAN}Доступні режими шифрування:{C_RESET}")
        print("  1 - Проста заміна (ECB)")
        print("  2 - Гамування (CTR)")
        print("  3 - Гамування зі зворотним зв'язком (CFB)")
        mode_input = input("Оберіть режим (1, 2, 3) [Enter = 3 (CFB)]: ").strip()

        if mode_input == '1':
            mode = 'ECB'
        elif mode_input == '2':
            mode = 'CTR'
        else:
            mode = 'CFB'

        # --- ЗАПИТ КЛЮЧА (З ТЕОРІЄЮ ТА ВАРІАНТАМИ) ---
        print(f"\n{C_CYAN}[НАЛАШТУВАННЯ СЕКРЕТНОГО КЛЮЧА]{C_RESET}")
        print(f"{C_YELLOW}💡 Теорія: Ключ для ГОСТ 28147:2009 повинен мати довжину строго 32 байти (256 біт).{C_RESET}")
        print(
            f"{C_YELLOW}Найвищу безпеку забезпечують випадкові набори символів (висока ентропія), оскільки їх неможливо підібрати за словником.{C_RESET}")
        print("Оберіть один із надійних шаблонів або введіть свій:")
        print(
            f"  {C_GREEN}[1]{C_RESET} Kj8#vL9$mP2@xZ5*qW1!eR4^tY7&uI0+ {C_CYAN}(Максимальна стійкість, випадковий набір){C_RESET}")
        print(
            f"  {C_GREEN}[2]{C_RESET} GOST_28147_89_SECRET_KEY_32BYTES {C_CYAN}(Середня стійкість, форматна фраза){C_RESET}")
        print(
            f"  {C_GREEN}[3]{C_RESET} 0123456789ABCDEF0123456789ABCDEF {C_CYAN}(Шістнадцятковий, для тестування та дебагу){C_RESET}")

        key_choice = input("Введіть номер (1-3) або напишіть власний ключ [Enter = 1]: ").strip()

        if key_choice == '1' or not key_choice:
            key_str = "Kj8#vL9$mP2@xZ5*qW1!eR4^tY7&uI0+"
        elif key_choice == '2':
            key_str = "GOST_28147_89_SECRET_KEY_32BYTES"
        elif key_choice == '3':
            key_str = "0123456789ABCDEF0123456789ABCDEF"
        else:
            key_str = key_choice.ljust(32, '_')[:32]
            print(f"{C_YELLOW} ↳ Ваш ключ автоматично адаптовано до 32 байт: {key_str}{C_RESET}")

        key = key_str.encode('utf-8')

        # --- ЗАПИТ ВЕКТОРА (З ТЕОРІЄЮ ТА ВАРІАНТАМИ) ---
        print(f"\n{C_CYAN}[НАЛАШТУВАННЯ ВЕКТОРА ІНІЦІАЛІЗАЦІЇ (IV)]{C_RESET}")
        print(
            f"{C_YELLOW}💡 Теорія: IV необхідний для режимів гамування (CTR, CFB), щоб гарантувати різний шифротекст{C_RESET}")
        print(
            f"{C_YELLOW}навіть для однакових файлів. Має бути рівно 8 байт (64 біти). Не обов'язково таємний, але має бути унікальним.{C_RESET}")
        print("Оберіть вектор:")
        print(f"  {C_GREEN}[1]{C_RESET} 7x!9Qa@2 {C_CYAN}(Випадковий рядок, найкращий вибір для безпеки){C_RESET}")
        print(f"  {C_GREEN}[2]{C_RESET} INIT_VEC {C_CYAN}(Текстовий формат, добре для базових перевірок){C_RESET}")
        print(
            f"  {C_GREEN}[3]{C_RESET} 00000001 {C_CYAN}(Лічильник, ідеально для покрокового аналізу алгоритму){C_RESET}")

        iv_choice = input("Введіть номер (1-3) або напишіть власний вектор [Enter = 1]: ").strip()

        if iv_choice == '1' or not iv_choice:
            iv_str = "7x!9Qa@2"
        elif iv_choice == '2':
            iv_str = "INIT_VEC"
        elif iv_choice == '3':
            iv_str = "00000001"
        else:
            iv_str = iv_choice.ljust(8, '_')[:8]
            print(f"{C_YELLOW} ↳ Ваш вектор автоматично адаптовано до 8 байт: {iv_str}{C_RESET}")

        iv = iv_str.encode('utf-8')

        # --- ВИКОНАННЯ ---
        if is_encrypt:
            out_file = in_file + ".enc"
        else:
            out_file = in_file.replace(".enc", "") + ".dec"

        try:
            with open(in_file, "rb") as f:
                data_in = f.read()

            data_out = process_data(data_in, key, iv, mode, is_encrypt)

            with open(out_file, "wb") as f:
                f.write(data_out)

            print(f"\n{C_GREEN}[+] УСПІХ! Файл оброблено.{C_RESET}")
            print(f"{C_GREEN}[+] Збережено як: {out_file}{C_RESET}")
        except Exception as e:
            print(f"\n{C_RED}[-] ПОМИЛКА: Неможливо обробити файл. {e}{C_RESET}")