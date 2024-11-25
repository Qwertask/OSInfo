import tkinter as tk
from tkinter import ttk, messagebox
import os
import psutil
import platform
import socket
import datetime
import json
import subprocess


#to do:убрать упрощения
def get_av_status():
    """Проверяет статус антивируса"""
    av_paths = {
        "Windows": ["C:\\Program Files\\Windows Defender\\MpCmdRun.exe"],
        "Linux": ["/usr/bin/clamscan"],
        "Darwin": ["/usr/local/bin/clamscan"]
    }
    current_platform = platform.system()
    av_installed = any(os.path.exists(path) for path in av_paths.get(current_platform, []))
    av_enabled = av_installed  # Упростим проверку для примера
    av_signatures_updated = av_installed  # Упростим проверку для примера
    return {
        "installed": av_installed,
        "enabled": av_enabled,
        "signatures_updated": av_signatures_updated
    }


#to do: MacOS check
def get_fw_status():
    """Проверяет статус файрвола"""
    current_platform = platform.system()
    if current_platform == "Windows":
        fw_enabled = os.system("netsh advfirewall show allprofiles state") == 0
    else:
        fw_enabled = os.system("ufw status") == 0  # Для Linux
    return {"enabled": fw_enabled}


def get_disk_encryption_status():
    """Проверяет статус шифрования диска"""
    current_platform = platform.system()
    encryption_status = False
    if current_platform == "Windows":
        encryption_status = os.system("manage-bde -status > nul") == 0
    elif current_platform == "Darwin":
        encryption_status = os.system("fdesetup status") == 0
    elif current_platform == "Linux":
        encryption_status = os.system("lsblk -o NAME,SIZE,TYPE,MOUNTPOINT,UUID,MODEL") == 0
    return {"disk_encryption": encryption_status}


def get_os_update_status():
    """Проверяет состояние обновлений ОС"""
    current_platform = platform.system()
    if current_platform == "Windows":
        updates_available = os.system("powershell -Command Get-WindowsUpdate") == 0
    elif current_platform == "Linux":
        updates_available = os.system("apt list --upgradable") == 0
    else:
        updates_available = False
    return {"os_updates": updates_available}


def get_hardware_info():
    """Получает информацию о процессоре, памяти, дисках и сети"""
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
    network_info = []
    for interface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET:
                network_info.append({
                    "name": interface,
                    "address": addr.address,
                    "type": "wireless" if 'wifi' in interface.lower() else "wired"
                })
    return {
        "cpu": cpu_info,
        "memory": memory_info,
        "disk": disk_info,
        "network": network_info
    }


def search_file(file_name):
    """Ищет файл в системных папках"""
    paths = os.environ["PATH"].split(os.pathsep)
    for path in paths:
        full_path = os.path.join(path, file_name)
        if os.path.exists(full_path):
            return {"found": True, "version": "1.0", "path": full_path}  # Условная версия
    return {"found": False}


def collect_system_info(checks, file_search=None):
    """Собирает информацию о системе на основе выбранных опций"""
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
    file_name = file_name_entry.get()
    file_search = None
    if file_name:
        file_search = search_file(file_name)

    info = collect_system_info(checks, file_search)

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
        for net in hardware['network']:
            formatted_info += f"  Network: {net['name']} ({net['type']}) - {net['address']}\n"
    if "file_search" in info:
        file_search = info["file_search"]
        formatted_info += f"File Search:\n  Found: {'Yes' if file_search['found'] else 'No'}\n"
        formatted_info += f"  Path: {file_search['path']}\n"
        formatted_info += f"  Version: {file_search['version']}\n"
    return formatted_info


def save_history():
    """Сохраняет историю в файл"""
    with open("history.json", "w", encoding="utf-8") as f:
        json.dump(history_data, f, indent=4, ensure_ascii=False)


def load_history():
    """Загружает историю из файла"""
    global history_data
    if os.path.exists("history.json"):
        with open("history.json", "r", encoding="utf-8") as f:
            history_data = json.load(f)


def show_history():
    """Показывает историю поисков"""
    history_window = tk.Toplevel(app)
    history_window.title("История поиска")
    history_text = tk.Text(history_window, width=80, height=20)
    history_text.pack()

    for entry in history_data:
        history_text.insert(tk.END, json.dumps(entry, indent=4, ensure_ascii=False) + "\n" + "-" * 50 + "\n")


# Основной интерфейс
app = tk.Tk()
app.title("Информационная панель")

frame = ttk.Frame(app, padding="10")
frame.grid(row=0, column=0)

history_data = []
load_history()

# История
history_button = ttk.Button(app, text="История", command=show_history)
history_button.grid(row=0, column=1, padx=(10, 0))

# Поле для ввода имени файла и версии
file_name_label = ttk.Label(frame, text="Имя файла для поиска:")
file_name_label.grid(row=0, column=0, sticky="w")
file_name_entry = ttk.Entry(frame)
file_name_entry.grid(row=0, column=1, pady=5)

# Чекбоксы для включения проверок
av_var = tk.BooleanVar(value=True)
fw_var = tk.BooleanVar(value=True)
de_var = tk.BooleanVar(value=True)
os_var = tk.BooleanVar(value=True)
hw_var = tk.BooleanVar(value=True)

ttk.Checkbutton(frame, text="Антивирус", variable=av_var).grid(row=1, column=0, sticky="w")
ttk.Checkbutton(frame, text="Файрвол", variable=fw_var).grid(row=2, column=0, sticky="w")
ttk.Checkbutton(frame, text="Шифрование диска", variable=de_var).grid(row=3, column=0, sticky="w")
ttk.Checkbutton(frame, text="Обновления ОС", variable=os_var).grid(row=4, column=0, sticky="w")
ttk.Checkbutton(frame, text="Железо", variable=hw_var).grid(row=5, column=0, sticky="w")

# Кнопка для отображения информации
display_format = tk.StringVar(value="JSON")
ttk.Button(frame, text="Показать информацию", command=display_info).grid(row=6, column=0, columnspan=2, pady=10)

# Текстовое поле для вывода результата
result_text = tk.Text(frame, width=80, height=20, wrap=tk.WORD)
result_text.grid(row=7, column=0, columnspan=2, pady=(5, 10))

# Кнопка для копирования в буфер обмена
ttk.Button(frame, text="Копировать в буфер обмена",
           command=lambda: result_text.clipboard_clear() or result_text.clipboard_append(
               result_text.get("1.0", tk.END))).grid(row=8, column=0, columnspan=2, pady=(5, 0))

app.mainloop()

#to do: отдельная кнопка поиска для файла
#to do: вывод в консоль - только для тестов
#to do: кнопку истории привязать в углу и добавить к ней иконку