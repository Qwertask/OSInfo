import os
import platform

#multiplatform
def get_fw_status():
    current_platform = platform.system()
    if current_platform == "Windows":
        fw_enabled = os.system("netsh advfirewall show allprofiles state > nul 2>&1") == 0
    elif current_platform == "Linux":
        fw_enabled = os.system("ufw status | grep -i active > /dev/null 2>&1") == 0
    elif current_platform == "Darwin":
        fw_enabled = os.system("sudo pfctl -sr > /dev/null 2>&1") == 0
    else:
        fw_enabled = False
    return {"enabled": fw_enabled}
