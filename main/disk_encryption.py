import platform
import subprocess

#multiplatform
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

