import platform
import re
import subprocess
import psutil
import requests

#multipllatform
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

def get_external_ip():
    try:
        response = requests.get('https://api.ipify.org', timeout=5)  # Устанавливаем таймаут для запроса
        response.raise_for_status()  # Проверяем успешность запроса (код 200)
        return response.text  # Возвращаем внешний IP-адрес
    except requests.exceptions.RequestException:
        return "N/A"  # Возвращаем "N/A" в случае ошибки
