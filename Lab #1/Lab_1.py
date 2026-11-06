import os
import time

# --- Кольори для терміналу ---
CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'


class LFSR:
    def __init__(self, poly, seed):
        self.n = max(poly)
        self.taps = [p for p in poly if p != self.n]
        self.state = seed & ((1 << self.n) - 1)
        if self.state == 0:
            raise ValueError("Ініціалізуюче значення (seed) не може бути нульовим!")

    def get_bit(self):
        out_bit = self.state & 1
        new_bit = 0
        for tap in self.taps:
            new_bit ^= (self.state >> tap) & 1
        self.state = (self.state >> 1) | (new_bit << (self.n - 1))
        return out_bit

    def get_byte(self):
        byte_val = 0
        for i in range(8):
            byte_val |= (self.get_bit() << i)
        return byte_val


def generate_cool_text():
    print(f"\n{CYAN}[*] Генеруємо тестовий файл...{RESET}")
    cool_text = (
        "1899 рік. Дикий Захід вмирає. Епоха стрільців добігає кінця, поступаючись місцем закону та порядку. \n"
        "Але для тих, хто живе поза законом, цей новий світ — це клітка.\n"
    )
    filepath = os.path.abspath("wild_west_story.txt")
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(cool_text )
        print(f"{GREEN}[+] Файл успішно створено.{RESET}")
        print(f"{YELLOW}Натисніть на посилання, щоб відкрити його прямо зараз:{RESET} file://{filepath}")
    except Exception as e:
        print(f"{RED}[-] Помилка створення файлу: {e}{RESET}")


def get_available_files():
    files = []
    for f in os.listdir('../..'):
        if os.path.isfile(f) and not f.startswith('.') and not f.endswith('.py'):
            files.append(f)
    return sorted(files)


def choose_lfsr_config():
    print(f"\n{CYAN}=== ВИБІР ПАРАМЕТРІВ РЗЛЗЗ ==={RESET}")
    print("Оберіть один з готових робочих варіантів з методички:")
    print(
        f"  {GREEN}[1]{RESET} 32-бітний регістр: Многочлен (32, 7, 5, 3, 2, 1, 0), Seed: 999999 (Максимальна надійність)")
    print(f"  {GREEN}[2]{RESET} 16-бітний регістр: Многочлен (16, 5, 3, 2, 0),       Seed: 12345  (Середня надійність)")
    print(f"  {GREEN}[3]{RESET} 8-бітний регістр:  Многочлен (8, 4, 3, 2, 0),        Seed: 42     (Для швидких тестів)")

    choice = input(f"\n{YELLOW}Введіть номер конфігурації (1-3) [за замовчуванням 1]: {RESET}").strip()

    if choice == '2':
        return [16, 5, 3, 2, 0], 12345
    elif choice == '3':
        return [8, 4, 3, 2, 0], 42
    else:
        return [32, 7, 5, 3, 2, 1, 0], 999999


def process_file(mode):
    action_name = "ШИФРУВАННЯ" if mode == "encrypt" else "ДЕШИФРУВАННЯ"
    print(f"\n{CYAN}=== КРОК 1: {action_name} ФАЙЛУ ==={RESET}")
    files = get_available_files()

    if not files:
        print(f"{RED}[-] У цій папці немає файлів. Згенеруйте тестовий текст (Опція 1).{RESET}")
        return

    print("Доступні файли:")
    for i, f in enumerate(files, 1):
        print(f"  {GREEN}[{i}]{RESET} {f}")

    file_choice = input(f"\n{YELLOW}Введіть НОМЕР файлу для {action_name.lower()}: {RESET}").strip()

    try:
        idx = int(file_choice) - 1
        in_filename = files[idx]
    except (ValueError, IndexError):
        print(f"{RED}[-] Невірний вибір. Операцію скасовано.{RESET}")
        return

    # Формування імені вихідного файлу
    base, ext = os.path.splitext(in_filename)
    if mode == "encrypt":
        out_filename = f"{base}_encrypted{ext}"
    else:
        out_filename = in_filename.replace("_encrypted",
                                           "_decrypted") if "_encrypted" in in_filename else f"decrypted_{in_filename}"

    # Вибір ключів
    poly, seed = choose_lfsr_config()

    print(f"\n{CYAN}[*] ПОЯСНЕННЯ ПРОЦЕСУ:{RESET}")
    if mode == "encrypt":
        print(f" 1. Програма зчитує оригінальний файл {BOLD}{in_filename}{RESET} по байтах (Відкритий текст).")
        print(f" 2. РЗЛЗЗ на базі многочлена {poly} генерує псевдовипадкову послідовність (Гамму).")
        print(" 3. Виконується операція XOR: Шифротекст = Відкритий текст ⊕ Гамма.")
    else:
        print(f" 1. Програма зчитує зашифрований файл {BOLD}{in_filename}{RESET} по байтах (Шифротекст).")
        print(f" 2. РЗЛЗЗ генерує АБСОЛЮТНО ТУ САМУ послідовність (Гамму), бо використані ті самі ключі.")
        print(" 3. Операція XOR знімає шифр: Відкритий текст = Шифротекст ⊕ Гамма.")

    time.sleep(2)  # Пауза, щоб встигнути прочитати

    # Запуск процесу
    try:
        lfsr = LFSR(poly, seed)
        print(f"\n{CYAN}[*] Виконую {action_name.lower()}...{RESET}")

        with open(in_filename, 'rb') as f_in, open(out_filename, 'wb') as f_out:
            while True:
                chunk = f_in.read(2048)
                if not chunk:
                    break
                out_chunk = bytearray(byte ^ lfsr.get_byte() for byte in chunk)
                # Примусове збереження на диск минаючи кеш ОС
                f_out.write(out_chunk)
                f_out.flush()
                os.fsync(f_out.fileno())

        abs_path = os.path.abspath(out_filename)
        print(f"{GREEN}[+] УСПІХ! Операцію завершено.{RESET}")
        print(f"{YELLOW}Ваш файл готовий, натисніть на посилання, щоб відкрити:{RESET} file://{abs_path}")

    except Exception as e:
        print(f"{RED}[-] Сталася помилка: {e}{RESET}")


def main():
    while True:

        print(f"{BOLD}{CYAN}      ПОТОКОВЕ ШИФРУВАННЯ РЗЛЗЗ          {RESET}")
        print(f"{BOLD}{CYAN}===================================================={RESET}")
        print(f" {GREEN}1.{RESET} Створити файл .txt")
        print(f" {GREEN}2.{RESET} ШИФРУВАТИ файл")
        print(f" {GREEN}3.{RESET} ДЕШИФРУВАТИ файл")
        print(f" {GREEN}0.{RESET} Вийти")
        print("")
        choice = input(f"{YELLOW}Оберіть дію (0-3): {RESET}").strip()

        if choice == '1':
            generate_cool_text()
        elif choice == '2':
            process_file("encrypt")
        elif choice == '3':
            process_file("decrypt")
        elif choice == '0':
            print(f"{CYAN}[*] Роботу завершено.{RESET}")
            break
        else:
            print(f"{RED}[-] Невідома команда.{RESET}")


if __name__ == "__main__":
    main()