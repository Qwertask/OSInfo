import platform
import subprocess

#multiplatform
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
        if "ProductStatus                    : 524288" in output.decode():
            av_status["signatures_updated"] = True
        if "ProductStatus                    : 1" in output.decode():
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
