"""Windows-only security boundary. The interactive process never loads the key."""
from __future__ import annotations

import json
import os
import subprocess
import time
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request, build_opener, HTTPRedirectHandler
from urllib.error import HTTPError

import win32api
import win32con
import win32crypt
import win32file
import win32pipe
import win32security
import win32service
import win32ts
import pywintypes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

PIPE = r"\\.\pipe\RemoteConsentAgent-v1"
MAX_MESSAGE = 262144
DATA = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "RemoteConsentAgent"


def system_only():
    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
    sid = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
    if win32security.ConvertSidToStringSid(sid) != "S-1-5-18":
        raise PermissionError("service_context_required")


def protect_directory(path: Path):
    path.mkdir(parents=True, exist_ok=True)
    descriptor = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
        "D:P(A;OICI;FA;;;SY)", win32security.SDDL_REVISION_1)
    win32security.SetFileSecurity(str(path), win32security.DACL_SECURITY_INFORMATION
                                  | win32security.PROTECTED_DACL_SECURITY_INFORMATION, descriptor)


def device_key(path: Path):
    system_only()
    protect_directory(path.parent)
    if path.exists():
        raw = win32crypt.CryptUnprotectData(path.read_bytes(), None, None, None, 0)[1]
        return Ed25519PrivateKey.from_private_bytes(raw)
    key = Ed25519PrivateKey.generate()
    raw = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                            serialization.NoEncryption())
    protected = win32crypt.CryptProtectData(raw, "Remote Consent Agent device key", None, None, None, 4)
    with path.open("xb") as output:
        output.write(protected)
    return key


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError("redirect_refused")


def https_url(url: str):
    parsed = urlsplit(url)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.fragment or parsed.query):
        raise ValueError("invalid_https_endpoint")
    return url


def post(endpoint, body, bearer=None):
    https_url(endpoint)
    headers = {"Content-Type": "application/json"}
    if bearer:
        headers["Authorization"] = "Bearer " + bearer
    request = Request(endpoint, json.dumps(body, ensure_ascii=False).encode(), headers, method="POST")
    # Default certificate validation, no redirects, no exception body logging.
    try:
        response = build_opener(NoRedirect()).open(request, timeout=5)
    except HTTPError as error:
        stamp = error.headers.get("Date")
        if stamp and abs(parsedate_to_datetime(stamp).timestamp() - time.time()) > 60:
            raise ValueError("clock_not_synchronized") from None
        raise ValueError("server_refused") from None
    with response:
        data = response.read(MAX_MESSAGE + 1)
        if len(data) > MAX_MESSAGE:
            raise ValueError("response_too_large")
        result = json.loads(data)
        if not isinstance(result, dict) or result.get("error") or result.get("ok") is False:
            raise ValueError("server_refused")
        return result


def pipe_attributes():
    attributes = pywintypes.SECURITY_ATTRIBUTES()
    attributes.SECURITY_DESCRIPTOR = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
        "D:P(A;;GA;;;SY)(A;;GRGW;;;BA)(A;;GRGW;;;IU)", win32security.SDDL_REVISION_1)
    return attributes


def caller(pipe):
    win32security.ImpersonateNamedPipeClient(pipe)
    try:
        token = win32security.OpenThreadToken(win32api.GetCurrentThread(), win32con.TOKEN_QUERY, True)
        session = win32security.GetTokenInformation(token, win32security.TokenSessionId)
        admin = win32security.CheckTokenMembership(token, win32security.CreateWellKnownSid(
            win32security.WinBuiltinAdministratorsSid))
        return session, bool(admin)
    finally:
        win32security.RevertToSelf()


def process_executable(pid):
    import ctypes
    from ctypes import wintypes
    process = win32api.OpenProcess(0x1000, False, pid)
    try:
        query_path = ctypes.windll.kernel32.QueryFullProcessImageNameW
        query_path.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
        query_path.restype = wintypes.BOOL
        path, length = ctypes.create_unicode_buffer(32768), wintypes.DWORD(32768)
        if not query_path(int(process), 0, path, ctypes.byref(length)):
            raise PermissionError("process_identity_unavailable")
        return Path(path.value).resolve()
    finally:
        process.Close()


def pipe_information(pipe, name):
    import ctypes
    from ctypes import wintypes
    value = wintypes.DWORD()
    query = getattr(ctypes.windll.kernel32, name)
    query.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    query.restype = wintypes.BOOL
    if not query(int(pipe), ctypes.byref(value)):
        raise PermissionError("pipe_identity_unavailable")
    return value.value


def trusted_ui(pipe):
    import sys
    pid = pipe_information(pipe, "GetNamedPipeClientProcessId")
    return getattr(sys, "frozen", False) and process_executable(pid) == Path(sys.executable).resolve()


def verify_pipe_server(pipe):
    import re
    # Authenticate the server before sending even the first byte of an owner
    # token. A same-user process must not squat the public pipe name.
    if pipe_information(pipe, "GetNamedPipeServerSessionId") != 0:
        raise PermissionError("service_context_required")
    manager = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT)
    service = None
    try:
        service = win32service.OpenService(manager, "RemoteConsentAgent", win32service.SERVICE_QUERY_CONFIG)
        configuration = win32service.QueryServiceConfig(service)
        match = re.fullmatch(r'"([^"\r\n]+)" --service', configuration[3])
        if not match or configuration[7].lower() not in ("localsystem", "nt authority\\system"):
            raise PermissionError("service_identity_mismatch")
        server_pid = pipe_information(pipe, "GetNamedPipeServerProcessId")
        if process_executable(server_pid) != Path(match[1]).resolve():
            raise PermissionError("service_identity_mismatch")
    finally:
        if service is not None:
            win32service.CloseServiceHandle(service)
        win32service.CloseServiceHandle(manager)


def active_session(session):
    return session != 0 and any(entry["SessionId"] == session and entry["State"] == win32ts.WTSActive
                                for entry in win32ts.WTSEnumerateSessions(None, 1, 0))


def ipc(body):
    deadline = time.monotonic() + 1.5
    while True:
        try:
            win32pipe.WaitNamedPipe(PIPE, 1500)
            handle = win32file.CreateFile(PIPE, win32con.GENERIC_READ | win32con.GENERIC_WRITE, 0, None,
                                          win32con.OPEN_EXISTING, 0x00110000, None)
            break
        except pywintypes.error as error:
            # The single server instance briefly disappears between clients.
            # Retry only opening: no credential/command has been sent yet.
            if error.winerror not in (2, 121, 231, 232, 233) or time.monotonic() >= deadline:
                raise
            time.sleep(.02)
    try:
        verify_pipe_server(handle)
        win32pipe.SetNamedPipeHandleState(handle, win32pipe.PIPE_READMODE_MESSAGE, None, None)
        win32file.WriteFile(handle, json.dumps(body, ensure_ascii=False).encode())
        data = win32file.ReadFile(handle, MAX_MESSAGE)[1]
        result = json.loads(data)
        if result.get("error"):
            raise ValueError(result["error"])
        return result
    finally:
        handle.Close()


def input_desktop_unlocked():
    import ctypes
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    user32.OpenInputDesktop.restype = ctypes.c_void_p
    desktop = user32.OpenInputDesktop(0, False, 0x0001)
    if not desktop:
        return False
    try:
        name = ctypes.create_unicode_buffer(256)
        needed = ctypes.c_ulong()
        return bool(user32.GetUserObjectInformationW(ctypes.c_void_p(desktop), 2, name,
                    ctypes.sizeof(name), ctypes.byref(needed))) and name.value == "Default"
    finally:
        user32.CloseDesktop(ctypes.c_void_p(desktop))


def publisher_info(path: Path):
    """Ask Windows to validate Authenticode and its trust chain."""
    import base64
    literal = str(path.resolve()).replace("'", "''")
    script = ("$ErrorActionPreference='Stop'; $s=Get-AuthenticodeSignature -LiteralPath '" + literal
              + "'; if($s.Status -ne 'Valid'){exit 3}; $v=[Diagnostics.FileVersionInfo]::GetVersionInfo('"
              + literal + "'); @{thumbprint=$s.SignerCertificate.Thumbprint;version=$v.FileVersion} | ConvertTo-Json -Compress")
    encoded = base64.b64encode(script.encode("utf-16-le")).decode()
    # A PS7 -> Python -> Windows PowerShell chain inherits PS7's module paths;
    # Windows PowerShell then loads incompatible Core modules. Let the stock
    # Windows shell rebuild its own default paths, as Microsoft documents.
    process_environment = {key: value for key, value in os.environ.items() if key.upper() != "PSMODULEPATH"}
    shell = Path(win32api.GetWindowsDirectory()) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    run = subprocess.run([str(shell), "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
                         env=process_environment, capture_output=True,
                         creationflags=subprocess.CREATE_NO_WINDOW, timeout=30)
    if run.returncode:
        raise ValueError("signature_refused")
    return json.loads(run.stdout.decode("utf-8-sig"))


def update_allowed(path, publisher, current_version, busy):
    if busy or not publisher:
        return False
    try:
        info = publisher_info(Path(path))
        def version(value):
            parts = [int(part) for part in value.split(".")]
            if not 1 <= len(parts) <= 4 or any(part < 0 or part > 65535 for part in parts):
                raise ValueError("invalid_version")
            return tuple(parts + [0] * (4 - len(parts)))
        return (info["thumbprint"].upper() == publisher.upper()
                and version(info["version"]) > version(current_version))
    except Exception:
        return False


def installed_ui_after_update():
    import sys
    import re
    import winreg
    if not getattr(sys, "frozen", False):
        return None
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run") as key:
            value = winreg.QueryValueEx(key, "RemoteConsentAgent")[0]
        match = re.fullmatch(r'"([^"\r\n]+)"', value)
        if not match:
            return None
        path = Path(match[1]).resolve()
        current = Path(sys.executable).resolve()
        if path != current and path.parent.parent == current.parent.parent and path.is_file():
            return str(path)
    except Exception:
        pass
    return None
