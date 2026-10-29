import json
import os
import shutil
import subprocess
import sys
import time
import winreg
from pathlib import Path

import win32api
import win32con
import win32security
import win32service
import win32serviceutil

from ui import VERSION
from windows_host import DATA, https_url, ipc, update_allowed

SERVICE = "RemoteConsentAgent"
RUN = r"Software\Microsoft\Windows\CurrentVersion\Run"


def administrator():
    if not win32security.CheckTokenMembership(None, win32security.CreateWellKnownSid(win32security.WinBuiltinAdministratorsSid)):
        raise PermissionError("administrator_required")


def program_files_root():
    import ctypes
    directory = ctypes.create_unicode_buffer(32768)
    if ctypes.windll.shell32.SHGetFolderPathW(None, 0x26, None, 0, directory) != 0:
        raise ValueError("program_files_unavailable")
    return Path(directory.value).resolve()


def safe_root(root):
    root = Path(root).resolve()
    # Only a dedicated named installation folder. Never recursively operate on
    # a parent, drive root, agent directory, repo root or arbitrary user input.
    if (root.name not in ("RemoteConsentAgent", "RemoteConsentAgentTest")
            or root.parent != program_files_root() or root.is_symlink()):
        raise ValueError("dedicated_install_directory_required")
    return root


def install(root, configuration, trusted_key, upgrade=False):
    administrator()
    if not getattr(sys, "frozen", False):
        raise ValueError("packaged_build_required")
    root = safe_root(root)
    if upgrade:
        config = json.loads((root / "config.json").read_text(encoding="utf-8-sig"))
        if not update_allowed(Path(sys.executable), config["publisher"], config["version"], False):
            raise ValueError("signature_refused")
    else:
        if root.exists():
            raise ValueError("already_installed")
        from enrollment_config import load_config
        verified = load_config(configuration, trusted_key)
        config = dict(verified, signed_config=json.loads(configuration.read_text(encoding='utf-8-sig')),
                      config_key=trusted_key)
        print('Installs a LocalSystem consent service and a sign-in tray application. '
              'It contacts the configured server, sending signed device/organization IDs, '
              'consent decisions and presence. Branding images contact the configured image hosts. '
              'No screen capture or remote-control engine is included. '
              'Use --uninstall after signed broker unenrollment to remove it.')
        root.mkdir(parents=True)
    # Program files must never be writable by ordinary users: otherwise a
    # replacement binary/config would execute as LocalSystem.
    descriptor = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
        "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)", 1)
    win32security.SetFileSecurity(str(root), win32security.DACL_SECURITY_INFORMATION
                                  | win32security.PROTECTED_DACL_SECURITY_INFORMATION, descriptor)
    win32security.SetNamedSecurityInfo(str(root), win32security.SE_FILE_OBJECT,
        win32security.OWNER_SECURITY_INFORMATION,
        win32security.CreateWellKnownSid(win32security.WinBuiltinAdministratorsSid), None, None, None)
    version_dir = root / VERSION
    version_dir.mkdir(exist_ok=False)
    executable = version_dir / "RemoteConsentAgent.exe"
    shutil.copy2(sys.executable, executable)
    config.update(version=VERSION, install_root=str(root))
    for destination in (root / "config.json", version_dir / "config.json"):
        destination.write_text(json.dumps(config), encoding="utf-8")
    if upgrade:
        win32serviceutil.StopService(SERVICE)
        win32serviceutil.WaitForServiceStatus(SERVICE, win32service.SERVICE_STOPPED, 30)
        manager = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT)
        service = win32service.OpenService(manager, SERVICE, win32service.SERVICE_CHANGE_CONFIG)
        try:
            win32service.ChangeServiceConfig(service, win32service.SERVICE_NO_CHANGE, win32service.SERVICE_NO_CHANGE,
                win32service.SERVICE_NO_CHANGE, f'"{executable}" --service', None, 0, None, None, None, None)
        finally:
            win32service.CloseServiceHandle(service)
            win32service.CloseServiceHandle(manager)
    else:
        win32serviceutil.InstallService(None, SERVICE, "Remote Consent Agent consent", exeName=str(executable),
            exeArgs="--service", startType=win32service.SERVICE_AUTO_START)
    with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, RUN, 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, SERVICE, 0, winreg.REG_SZ, f'"{executable}"')
    win32serviceutil.StartService(SERVICE)
    print("Component installed; owner enrollment is still required")


def uninstall(root):
    administrator()
    root = safe_root(root)
    # Keep both executable and protected key until a signed broker response
    # confirms all shares ended and native fallback was restored.
    result = ipc({"action": "unenroll"})
    if result.get("state") != "unenrolled":
        raise ValueError("disconnect_pending")
    # Allow the installed customer UI to observe the signed completion and exit
    # itself. Never kill unrelated processes or touch the Support agent.
    time.sleep(2)
    win32serviceutil.StopService(SERVICE)
    win32serviceutil.WaitForServiceStatus(SERVICE, win32service.SERVICE_STOPPED, 30)
    win32serviceutil.RemoveService(SERVICE)
    with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, RUN, 0, winreg.KEY_SET_VALUE) as key:
        winreg.DeleteValue(key, SERVICE)
    # The caller runs the installer from outside the install directory. An
    # in-use UI file is reported rather than killed or silently left behind.
    # SCM can report stopped before the one-file bootloader releases its image.
    # Wait briefly for that known installation; never kill another process.
    deadline = time.monotonic() + 10
    while True:
        try:
            shutil.rmtree(root)
            break
        except PermissionError as error:
            if error.winerror not in (5, 32) or time.monotonic() >= deadline:
                raise
            time.sleep(.2)
    if DATA.exists():
        raise ValueError("protected_state_not_removed")
    print("Component and device key removed")


def check_update(config, busy, prepare):
    from urllib.request import build_opener
    from windows_host import NoRedirect
    if busy or not config.get("publisher"):
        return False
    source = https_url(config["update_source"])
    destination = DATA / "update.exe"
    limit = 100 * 1024 * 1024
    with build_opener(NoRedirect()).open(source, timeout=10) as response, destination.open("wb") as output:
        total = 0
        while chunk := response.read(65536):
            total += len(chunk)
            if total > limit:
                raise ValueError("update_too_large")
            output.write(chunk)
    if not update_allowed(destination, config["publisher"], config["version"], busy):
        destination.unlink(missing_ok=True)
        return False
    if not prepare():
        return False
    subprocess.Popen([str(destination), "--upgrade", config["install_root"]],
                     creationflags=subprocess.CREATE_NO_WINDOW)
    return True
