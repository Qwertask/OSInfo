import tkinter as tk
from tkinter import ttk, messagebox
import os
import psutil
import platform
import re
import datetime
import json
import subprocess
import pefile
import locale
import requests
locale.setlocale(locale.LC_ALL, 'ru_RU.UTF-8')
subprocess.run('chcp 65001', shell=True)



def get_external_ip():
    try:
        response = requests.get('https://api.ipify.org', timeout=5)  # Устанавливаем таймаут для запроса
        response.raise_for_status()  # Проверяем успешность запроса (код 200)
        return response.text  # Возвращаем внешний IP-адрес
    except requests.exceptions.RequestException:
        return "N/A"  # Возвращаем "N/A" в случае ошибки

def display_info():
    """Отображает собранную информацию в текстовом поле"""
    checks = {
        "antivirus": av_var.get(),
        "firewall": fw_var.get(),
        "disk_encryption": de_var.get(),
        "os_updates": os_var.get(),
        "hardware": hw_var.get()
    }

    # Если нужно выполнить поиск файла
    info = collect_system_info(checks)

    # Сохраняем информацию в файл истории
    history_data.append(info)
    save_history()

    result_text.delete(1.0, tk.END)
    if display_format.get() == 'JSON':
        info_json = json.dumps(info, indent=4, ensure_ascii=False)
        result_text.insert(tk.END, info_json)
    else:
        formatted_info = format_info(info)
        result_text.insert(tk.END, formatted_info)


def format_info(info):
    """Форматирует информацию для вывода в текстовом формате"""
    formatted_info = f"Timestamp: {info['timestamp']}\n\n"
    if "antivirus" in info:
        formatted_info += f"Antivirus:\n  Installed: {'Yes' if info['antivirus']['installed'] else 'No'}\n"
        formatted_info += f"  Enabled: {'Yes' if info['antivirus']['enabled'] else 'No'}\n"
        formatted_info += f"  Signatures Updated: {'Yes' if info['antivirus']['signatures_updated'] else 'No'}\n\n"
    if "firewall" in info:
        formatted_info += f"Firewall:\n  Enabled: {'Yes' if info['firewall']['enabled'] else 'No'}\n\n"
    if "disk_encryption" in info:
        formatted_info += f"Disk Encryption: {'Yes' if info['disk_encryption']['disk_encryption'] else 'No'}\n\n"
    if "os_updates" in info:
        formatted_info += f"OS Updates: {'Up to Date' if info['os_updates']['os_updates'] else 'Not Up to Date'}\n\n"
    if "hardware" in info:
        hardware = info['hardware']
        formatted_info += f"Hardware Info:\n  CPU Cores: {hardware['cpu']['cores']}\n"
        formatted_info += f"  RAM: {hardware['memory']['percent']}% used ({hardware['memory']['used'] / (1024 ** 3):.2f} GB / {hardware['memory']['total'] / (1024 ** 3):.2f} GB)\n"
        formatted_info += f"  Disk: {hardware['disk']['percent_used']}% used ({hardware['disk']['free'] / (1024 ** 3):.2f} GB free / {hardware['disk']['total'] / (1024 ** 3):.2f} GB total)\n"
        formatted_info += "Network Info:\n"
        for net in hardware['network']:
            formatted_info += f"  Name: {net['name']}\n  Type: {net['type']}\n  Address: {net['address']}\n\n"
    return formatted_info



def check_windows_av():
    av_status = {
        "installed": False,
        "enabled": False,
        "signatures_updated": False
    }

    try:
        output = subprocess.check_output("powershell Get-MpComputerStatus", shell=True)
        if "AMServiceEnabled                 : True" in output.decode():
            av_status["installed"] = True
            av_status["enabled"] = True
        if "AntivirusSignatureVersion" in output.decode():
            av_status["signatures_updated"] = True
    except subprocess.CalledProcessError:
        pass

    return av_status


def check_macos_av():
    av_status = {
        "installed": False,
        "enabled": False,
        "signatures_updated": False
    }

    try:
        output = subprocess.check_output("/usr/bin/sweep -v", shell=True)
        if "Sophos" in output.decode():
            av_status["installed"] = True
            av_status["enabled"] = True
        if "Updated" in output.decode():
            av_status["signatures_updated"] = True
    except subprocess.CalledProcessError:
        pass

    return av_status


def check_linux_av():
    av_status = {
        "installed": False,
        "enabled": False,
        "signatures_updated": False
    }

    try:
        output = subprocess.check_output("clamdscan --version", shell=True)
        if "ClamAV" in output.decode():
            av_status["installed"] = True
            av_status["enabled"] = True
        try:
            sig_output = subprocess.check_output("freshclam -v", shell=True)
            if "daily.cld" in sig_output.decode():
                av_status["signatures_updated"] = True
        except subprocess.CalledProcessError:
            pass
    except subprocess.CalledProcessError:
        pass

    return av_status


def get_av_status():
    current_platform = platform.system()
    if current_platform == "Windows":
        return check_windows_av()
    elif current_platform == "Darwin":
        return check_macos_av()
    elif current_platform == "Linux":
        return check_linux_av()
    else:
        return {
            "installed": False,
            "enabled": False,
            "signatures_updated": False
        }


def get_fw_status():
    current_platform = platform.system()
    if current_platform == "Windows":
        fw_enabled = os.system("netsh advfirewall show allprofiles state") == 0
    elif current_platform == "Linux":
        fw_enabled = os.system("ufw status | grep -i active") == 0
    elif current_platform == "Darwin":
        fw_enabled = os.system("sudo pfctl -sr > /dev/null 2>&1") == 0
    else:
        fw_enabled = False
    return {"enabled": fw_enabled}


def get_disk_encryption_status():
    current_platform = platform.system()
    encryption_status = False

    if current_platform == "Windows":
        try:
            output = subprocess.check_output("manage-bde -status", shell=True)
            encryption_status = "Fully Encrypted" in output.decode()
        except subprocess.CalledProcessError:
            encryption_status = False
    elif current_platform == "Darwin":
        try:
            output = subprocess.check_output("fdesetup status", shell=True, encoding='utf-8')
            encryption_status = "FileVault is On" in output
        except subprocess.CalledProcessError:
            encryption_status = False
    elif current_platform == "Linux":
        try:
            output = subprocess.check_output("lsblk -o TYPE", shell=True, encoding='utf-8')
            encryption_status = "crypt" in output
        except subprocess.CalledProcessError:
            encryption_status = False
    return {"disk_encryption": encryption_status}


def get_os_update_status():
    current_platform = platform.system()
    updates_available = False

    if current_platform == "Windows":
        try:
            output = subprocess.check_output("wmic qfe list brief /format:table", shell=True, encoding='cp1252')
            updates_available = len(output.strip().split('\n')) > 1
        except subprocess.CalledProcessError:
            updates_available = False
    elif current_platform == "Linux":
        try:
            output = subprocess.check_output("apt list --upgradable", shell=True, encoding='utf-8')
            updates_available = "upgradable" in output
        except subprocess.CalledProcessError:
            updates_available = False
    elif current_platform == "Darwin":
        try:
            output = subprocess.check_output("softwareupdate -l", shell=True, encoding='utf-8')
            updates_available = "Software Update found the following new or updated software" in output
        except subprocess.CalledProcessError:
            updates_available = False
    return {"os_updates": updates_available}

def get_active_network():
    """Возвращает активные сетевые интерфейсы с типом подключения (проводной или беспроводной)."""
    system = platform.system()
    network_info = []

    if system == "Windows":
        try:
            result = subprocess.check_output('netsh wlan show interfaces', shell=True, text=True, encoding="utf-8", errors="ignore")
            ssid_match = re.search(r"SSID\s*:\s*(.+)", result)
            state_match = re.search(r"State\s*:\s*(.+)", result)
            if ssid_match and state_match and "connected" in state_match.group(1).lower():
                network_info.append({
                    'name': ssid_match.group(1),
                    'address': get_external_ip(),
                    'type': 'wireless'
                })
        except subprocess.CalledProcessError:
            pass

        try:
            result = subprocess.check_output('ipconfig', shell=True, text=True, encoding="utf-8", errors="ignore")
            ip_match = re.search(r"IPv4 Address[ .]*: (\d+\.\d+\.\d+\.\d+)", result)
            if "Ethernet adapter" in result and ip_match:
                network_info.append({
                    'name': 'Ethernet',
                    'address': ip_match.group(1),
                    'type': 'wired'
                })
        except subprocess.CalledProcessError:
            pass

    elif system == "Linux":
        try:
            result = subprocess.check_output(['iwconfig'], text=True, stderr=subprocess.DEVNULL)
            if 'no wireless extensions' not in result:
                ip_result = subprocess.check_output(['ip', 'addr'], text=True)
                ip_match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", ip_result)
                network_info.append({
                    'name': 'Wi-Fi',
                    'address': ip_match.group(1) if ip_match else "N/A",
                    'type': 'wireless'
                })
        except FileNotFoundError:
            pass

        try:
            result = subprocess.check_output(['ip', 'link'], text=True)
            ip_result = subprocess.check_output(['ip', 'addr'], text=True)
            ip_match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", ip_result)
            if "UP" in result:
                network_info.append({
                    'name': 'Ethernet',
                    'address': ip_match.group(1) if ip_match else "N/A",
                    'type': 'wired'
                })
        except subprocess.CalledProcessError:
            pass

    elif system == "Darwin":
        try:
            result = subprocess.check_output(['networksetup', '-listallhardwareports'], text=True)
            if "Wi-Fi" in result:
                ip_result = subprocess.check_output(['ifconfig'], text=True)
                ip_match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", ip_result)
                network_info.append({
                    'name': 'Wi-Fi',
                    'address': ip_match.group(1) if ip_match else "N/A",
                    'type': 'wireless'
                })
        except FileNotFoundError:
            pass

        try:
            result = subprocess.check_output(['ifconfig'], text=True)
            ip_match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", result)
            if "en0" in result and "status: active" in result:
                network_info.append({
                    'name': 'Ethernet',
                    'address': ip_match.group(1) if ip_match else "N/A",
                    'type': 'wired'
                })
        except subprocess.CalledProcessError:
            pass

    return network_info if network_info else [{"name": "No Network", "address": "N/A", "type": "N/A"}]


def get_hardware_info():
    """Собирает полную информацию о системе."""
    cpu_info = {
        "cores": psutil.cpu_count(logical=False),
    }
    memory = psutil.virtual_memory()
    memory_info = {
        "total": memory.total,
        "used": memory.used,
        "percent": memory.percent
    }
    disk = psutil.disk_usage('/')
    disk_info = {
        "total": disk.total,
        "free": disk.free,
        "percent_used": disk.percent
    }

    # Получаем информацию о текущей активной сети
    active_network = get_active_network()

    return {
        "cpu": cpu_info,
        "memory": memory_info,
        "disk": disk_info,
        "network": active_network
    }


def collect_system_info(checks, file_search=None):
    info = {"timestamp": datetime.datetime.now().isoformat()}
    if checks["antivirus"]:
        info["antivirus"] = get_av_status()
    if checks["firewall"]:
        info["firewall"] = get_fw_status()
    if checks["disk_encryption"]:
        info["disk_encryption"] = get_disk_encryption_status()
    if checks["os_updates"]:
        info["os_updates"] = get_os_update_status()
    if checks["hardware"]:
        info["hardware"] = get_hardware_info()
    if file_search:
        info["file_search"] = file_search
    return info


def save_history():
    with open("history.json", "w", encoding="utf-8") as f:
        json.dump(history_data, f, indent=4, ensure_ascii=False)


def load_history():
    global history_data
    if os.path.exists("history.json"):
        with open("history.json", "r", encoding="utf-8") as f:
            history_data = json.load(f)


def show_history():
    history_window = tk.Toplevel(app)
    history_window.title("История поиска")
    history_text = tk.Text(history_window, width=80, height=80)
    history_text.pack()
    for entry in history_data:
        history_text.insert(tk.END, json.dumps(entry, indent=4, ensure_ascii=False) + "\n" + "-" * 70 + "\n")

def format_info_as_table(info):
    formatted_info = "Информация о системе:\n\n"

    # Антивирус
    if "antivirus" in info:
        formatted_info += "Антивирус:\n"
        formatted_info += f"{'Установлен':<20}{'Включен':<20}{'Сигнатуры обновлены':<20}\n"
        formatted_info += f"{'Да' if info['antivirus']['installed'] else 'Нет':<20}"
        formatted_info += f"{'Да' if info['antivirus']['enabled'] else 'Нет':<20}"
        formatted_info += f"{'Да' if info['antivirus']['signatures_updated'] else 'Нет':<20}\n\n"

    # Файрвол
    if "firewall" in info:
        formatted_info += f"Файрвол:\n{'Включен':<20}{'Да' if info['firewall']['enabled'] else 'Нет':<20}\n\n"

    # Шифрование диска
    if "disk_encryption" in info:
        formatted_info += f"Шифрование диска:\n{'Да' if info['disk_encryption']['disk_encryption'] else 'Нет'}\n\n"

    # Обновления ОС
    if "os_updates" in info:
        formatted_info += f"Обновления ОС:\n{'Актуально' if info['os_updates']['os_updates'] else 'Не актуально'}\n\n"

    # Железо
    if "hardware" in info:
        formatted_info += "Железо:\n"
        hardware = info["hardware"]
        formatted_info += f"{'CPU (ядра)':<20}{hardware['cpu']['cores']}\n"
        formatted_info += f"{'RAM (используется)':<20}{hardware['memory']['percent']}%\n"
        formatted_info += f"{'Диск (используется)':<20}{hardware['disk']['percent_used']}%\n\n"

        # Сети
        formatted_info += "Сети:\n"
        if isinstance(hardware['network'], list):
            for net in hardware['network']:
                formatted_info += f"{net['name']:<20}{net['type']:<20}{net['address']:<20}\n"
        else:
            # Если сеть не в виде списка (например, один активный интерфейс)
            formatted_info += f"{hardware['network']:<20} {'wireless' if 'wireless' in hardware['network'] else 'wired'}\n"
    return formatted_info


def search_file_button_action():
    """Обработка нажатия кнопки 'Поиск'. Выполняет поиск файла по имени и выводит версию, если доступна."""
    file_name = file_name_entry.get()
    if not file_name:
        error_message = {"error": "Введите имя файла для поиска."}
        if display_format.get() == "JSON":
            result_text.delete(1.0, tk.END)
            result_text.insert(tk.END, json.dumps(error_message, indent=4, ensure_ascii=False))
        else:
            messagebox.showwarning("Ошибка", error_message["error"])
        return

    possible_extensions = [".exe", ""] if platform.system() == "Windows" else ["", ".sh", ".bin"]

    def extended_file_search(name):
        paths = os.environ["PATH"].split(os.pathsep)
        for path in paths:
            for ext in possible_extensions:
                full_path = os.path.join(path, name + ext)
                if os.path.isfile(full_path):
                    version = get_file_version(full_path)
                    return {"found": True, "path": full_path, "version": version or "Не указана"}
        return {"found": False}

    def get_file_version(file_path):
        if platform.system() == "Windows":
            return get_windows_product_version(file_path)
        else:
            return None  # Для Linux/Unix можно дополнительно реализовать аналогичный функционал

    def get_windows_product_version(file_path):
        try:
            pe = pefile.PE(file_path)

            # Извлечение VS_VERSION_INFO
            if hasattr(pe, 'VS_VERSIONINFO') and pe.VS_VERSIONINFO:
                for file_info in pe.FileInfo:
                    if isinstance(file_info, list):
                        for entry in file_info:
                            if entry.Key == b'StringFileInfo':
                                for string_table in entry.StringTable:
                                    if b'ProductVersion' in string_table.entries:
                                        return string_table.entries[b'ProductVersion'].decode()

        except Exception:
            return None

    try:
        file_search_result = extended_file_search(file_name)
        result_text.delete(1.0, tk.END)
        if display_format.get() == "JSON":
            result_text.insert(tk.END, json.dumps(file_search_result, indent=4, ensure_ascii=False))
        else:
            if file_search_result["found"]:
                result_text.insert(tk.END,
                                   f"Файл найден:\nПуть: {file_search_result['path']}\nВерсия: {file_search_result['version']}")
            else:
                result_text.insert(tk.END, "Файл не найден.")
    except Exception as e:
        error_message = {"error": f"Ошибка поиска файла: {str(e)}"}
        result_text.delete(1.0, tk.END)
        if display_format.get() == "JSON":
            result_text.insert(tk.END, json.dumps(error_message, indent=4, ensure_ascii=False))
        else:
            messagebox.showerror("Ошибка", error_message["error"])


app = tk.Tk()
app.title("Системная информация")
frame = ttk.Frame(app, padding=10)
frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

history_data = []
load_history()

ttk.Button(frame, text="Поиск файла", command=search_file_button_action).grid(row=9, column=2, pady=10)

av_var = tk.BooleanVar(value=True)
fw_var = tk.BooleanVar(value=True)
de_var = tk.BooleanVar(value=True)
os_var = tk.BooleanVar(value=True)
hw_var = tk.BooleanVar(value=True)

# Метки и чекбоксы для настроек
ttk.Label(frame, text="Параметры проверки:").grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 5))
ttk.Checkbutton(frame, text="Антивирус", variable=av_var).grid(row=1, column=0, sticky="w")
ttk.Checkbutton(frame, text="Файрвол", variable=fw_var).grid(row=1, column=1, sticky="w")
ttk.Checkbutton(frame, text="Шифрование диска", variable=de_var).grid(row=2, column=0, sticky="w")
ttk.Checkbutton(frame, text="Обновления ОС", variable=os_var).grid(row=2, column=1, sticky="w")
ttk.Checkbutton(frame, text="Железо", variable=hw_var).grid(row=3, column=0, sticky="w")

# Поле для ввода имени файла
ttk.Label(frame, text="Поиск файла:").grid(row=4, column=0, columnspan=2, sticky="w", pady=(10, 5))
file_name_entry = ttk.Entry(frame, width=40)
file_name_entry.grid(row=5, column=0, columnspan=2, sticky="w")

# Радиокнопки для формата вывода
display_format = tk.StringVar(value="JSON")
ttk.Label(frame, text="Формат вывода:").grid(row=6, column=0, columnspan=2, sticky="w", pady=(10, 5))
ttk.Radiobutton(frame, text="JSON", variable=display_format, value="JSON").grid(row=7, column=0, sticky="w")
ttk.Radiobutton(frame, text="Таблица", variable=display_format, value="Таблица").grid(row=7, column=1, sticky="w")

# Поле для отображения результата
result_text = tk.Text(frame, width=80, height=20)
result_text.grid(row=8, column=0, columnspan=3, pady=(10, 0))

# Кнопки
ttk.Button(frame, text="Показать информацию", command=lambda: display_info()).grid(row=9, column=0, pady=10)
ttk.Button(frame, text="История", command=show_history).grid(row=9, column=1, pady=10)

app.mainloop()

#to do: file search
#to do: antivirus version
