import ctypes
from ctypes import wintypes
import uuid

wintrust = ctypes.WinDLL("wintrust")

WTD_UI_NONE = 2

WTD_REVOKE_NONE = 0

WTD_CHOICE_FILE = 1

WTD_STATEACTION_IGNORE = 0

WTD_SAFER_FLAG = 0x00000100

WINTRUST_ACTION_GENERIC_VERIFY_V2 = uuid.UUID(
    "{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}"
)

def guid_to_ctypes(guid):

    class GUID(ctypes.Structure):

        _fields_ = [

            ("Data1", wintypes.DWORD),

            ("Data2", wintypes.WORD),

            ("Data3", wintypes.WORD),

            ("Data4", ctypes.c_ubyte * 8)

        ]

    data = guid.bytes_le

    return GUID.from_buffer_copy(data)

class WINTRUST_FILE_INFO(ctypes.Structure):

    _fields_ = [

        ("cbStruct", wintypes.DWORD),

        ("pcwszFilePath", wintypes.LPCWSTR),

        ("hFile", wintypes.HANDLE),

        ("pgKnownSubject", ctypes.c_void_p)

    ]

    def __init__(self, path):

        super().__init__()

        self.cbStruct = ctypes.sizeof(self)

        self.pcwszFilePath = path

        self.hFile = None

        self.pgKnownSubject = None

class WINTRUST_FILE_INFO(ctypes.Structure):

    _fields_ = [

        ("cbStruct", wintypes.DWORD),

        ("pcwszFilePath", wintypes.LPCWSTR),

        ("hFile", wintypes.HANDLE),

        ("pgKnownSubject", ctypes.c_void_p)

    ]

    def __init__(self, path):

        super().__init__()

        self.cbStruct = ctypes.sizeof(self)

        self.pcwszFilePath = path

        self.hFile = None

        self.pgKnownSubject = None

class WINTRUST_DATA(ctypes.Structure):

    _fields_ = [

        ("cbStruct", wintypes.DWORD),
        ("pPolicyCallbackData", ctypes.c_void_p),
        ("pSIPClientData", ctypes.c_void_p),
        ("dwUIChoice", wintypes.DWORD),
        ("fdwRevocationChecks", wintypes.DWORD),
        ("dwUnionChoice", wintypes.DWORD),
        ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
        ("dwStateAction", wintypes.DWORD),
        ("hWVTStateData", wintypes.HANDLE),
        ("pwszURLReference", wintypes.LPCWSTR),
        ("dwProvFlags", wintypes.DWORD),
        ("dwUIContext", wintypes.DWORD)

    ]

    def __init__(self, file_info):

        super().__init__()

        self.cbStruct = ctypes.sizeof(self)

        self.pPolicyCallbackData = None

        self.pSIPClientData = None

        self.dwUIChoice = WTD_UI_NONE

        self.fdwRevocationChecks = WTD_REVOKE_NONE

        self.dwUnionChoice = WTD_CHOICE_FILE

        self.pFile = ctypes.pointer(file_info)

        self.dwStateAction = WTD_STATEACTION_IGNORE

        self.hWVTStateData = None

        self.pwszURLReference = None

        self.dwProvFlags = WTD_SAFER_FLAG

        self.dwUIContext = 0

wintrust.WinVerifyTrust.argtypes = [
    wintypes.HWND,
    ctypes.c_void_p,
    ctypes.c_void_p
]

wintrust.WinVerifyTrust.restype = wintypes.LONG

def verify_signature(path):

    file_info = WINTRUST_FILE_INFO(path)

    trust_data = WINTRUST_DATA(file_info)

    guid = guid_to_ctypes(WINTRUST_ACTION_GENERIC_VERIFY_V2)

    result = wintrust.WinVerifyTrust(
        None,
        ctypes.byref(guid),
        ctypes.byref(trust_data)
    )

    return result