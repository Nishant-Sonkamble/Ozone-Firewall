import subprocess


def get_signature_info(file_path):

    if not file_path:
        return None, None

    command = [
        "powershell",
        "-Command",
        f"""
        $sig = Get-AuthenticodeSignature '{file_path}';
        Write-Output $sig.Status;
        Write-Output $sig.SignerCertificate.Subject;
        """
    ]

    try:

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=5
        )

        lines = result.stdout.strip().splitlines()

        status = lines[0].strip() if len(lines) > 0 else None
        publisher = lines[1].strip() if len(lines) > 1 else None

        return status, publisher

    except Exception:
        return None, None
    
TRUSTED_PUBLISHERS = [

    "Microsoft",

    "Google",

    "NVIDIA",

    "Epic Games",

    "Adobe",

    "Mozilla",

    "Oracle",

    "Intel",

    "AMD"

]



_signature_cache = {}

def is_trusted_process(file_path):

    if not file_path:
        return False, "Unknown"

    if file_path in _signature_cache:
        return _signature_cache[file_path]

    status, publisher = get_signature_info(file_path)

    if status != "Valid":
        result = (False, "Unsigned executable")
        _signature_cache[file_path] = result
        return result

    result = (True, publisher)

    _signature_cache[file_path] = result

    return result