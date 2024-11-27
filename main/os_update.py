import platform
import subprocess

#multiplatform
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