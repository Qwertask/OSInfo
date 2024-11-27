import platform
import re
import subprocess
import psutil
import requests

#multipllatform
def get_hardware_info():
    cpu_info = {
        "name": platform.processor(),
        "cores": psutil.cpu_count(logical=False),
        "usage_per_core": psutil.cpu_percent(interval=1, percpu=True)
    }
    memory_info = {
        "total": psutil.virtual_memory().total,
        "used": psutil.virtual_memory().used,
        "percent": psutil.virtual_memory().percent,
    }
    disk_info = {
        "disk": get_disk_info()
    }
    network_info = get_active_network()
    return {
        "cpu": cpu_info,
        "memory": memory_info,
        "disk": disk_info,
        "network": network_info
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


def get_disk_info():
    partitions = psutil.disk_partitions()
    disks = []
    for partition in partitions:
        usage = psutil.disk_usage(partition.mountpoint)
        disks.append({ "device": partition.device, "mountpoint": partition.mountpoint, "fstype": partition.fstype, "total": usage.total, "used": usage.used, "free": usage.free, "percent_used": usage.percent })
        return disks