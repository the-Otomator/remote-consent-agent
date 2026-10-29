import argparse
import getpass
import json
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--service", action="store_true")
    parser.add_argument("--gallery", type=Path)
    parser.add_argument("--enroll", action="store_true")
    parser.add_argument("--unenroll", action="store_true")
    parser.add_argument("--install", type=Path)
    parser.add_argument("--uninstall", type=Path)
    parser.add_argument("--upgrade", type=Path)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--config-key")
    args = parser.parse_args()
    if args.service:
        import servicemanager
        from service import ConsentService
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(ConsentService)
        servicemanager.StartServiceCtrlDispatcher()
    elif args.gallery:
        from ui import gallery
        gallery(args.gallery)
    elif args.enroll:
        from windows_host import ipc
        # No token in command arguments, URLs, clipboard or shell history.
        org = input("Organization UUID: ").strip()
        device = input("Device UUID: ").strip()
        session = getpass.getpass("Owner access token (hidden): ")
        ipc(dict(action="enroll", org_id=org, device_id=device, owner_session=session))
        print("Enrollment accepted")
    elif args.unenroll:
        from windows_host import ipc
        result = ipc(dict(action="unenroll"))
        print("Unenrolled" if result.get("state") == "unenrolled" else "Disconnect pending; retry before uninstall")
    elif args.install or args.upgrade:
        from installer import install
        install(args.install or args.upgrade, args.config, args.config_key,
                upgrade=bool(args.upgrade))
    elif args.uninstall:
        from installer import uninstall
        uninstall(args.uninstall)
    else:
        import ctypes
        import win32api
        import win32event
        instance = win32event.CreateMutex(None, False, "Global\\RemoteConsentAgentUI")
        if win32api.GetLastError() == 183:
            return
        ctypes.windll.kernel32.FreeConsole()
        from ui import CustomerUI
        ui = CustomerUI()
        ui.root.mainloop()
        instance.Close()
        if ui.restart:
            import subprocess
            subprocess.Popen([ui.restart], creationflags=subprocess.CREATE_NO_WINDOW)


if __name__ == "__main__":
    try:
        main()
    except Exception as failure:
        # Never print exception bodies: enrollment/network failures may carry
        # credentials. Console operator output is deliberately a fixed code.
        print("Operation refused. Verify enrollment, clock, permissions and server connection.", file=sys.stderr)
        if set(sys.argv) & {"--install", "--uninstall", "--upgrade"}:
            print("Operator diagnostic: " + type(failure).__name__ + " "
                  + str(getattr(failure, "winerror", 0)), file=sys.stderr)
        if "--gallery" in sys.argv and not set(sys.argv) & {"--service", "--enroll", "--unenroll", "--install", "--uninstall", "--upgrade"}:
            # Gallery fixtures contain no credentials; even here emit only the
            # exception class, never arbitrary exception messages or fields.
            print("Gallery diagnostic: " + type(failure).__name__, file=sys.stderr)
        sys.exit(1)
