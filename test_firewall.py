from windows_firewall import block_application,allow_application

notepad_path = r"C:\Windows\System32\notepad.exe"

success, out, err = allow_application(notepad_path)

print(success)
print(out)
print(err)