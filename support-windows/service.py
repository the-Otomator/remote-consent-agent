"""LocalSystem service and authenticated local named-pipe boundary."""
import json
import threading
import time
import pywintypes
from pathlib import Path

import win32event
import win32file
import win32pipe
import win32service
import win32serviceutil

from consent_client import ConsentState, DeviceSigner, identifier
from windows_host import (PIPE, MAX_MESSAGE, DATA, active_session, caller, device_key,
                          pipe_attributes, post, protect_directory, system_only, trusted_ui)


class Engine:
    def __init__(self, config):
        system_only()
        from enrollment_config import verify_config
        verified = verify_config(config['signed_config'], config['config_key'], installing=False)
        for key, value in verified.items():
            if config.get(key) != value:
                raise ValueError('configuration_tampered')
        self.config = config
        self.lock = threading.RLock()
        self.state = None
        self.last_ui = 0
        self.last_update = 0
        self.maintenance = False
        self.uninstall_complete = bool(config.get("uninstall_complete", False))
        self.stop = threading.Event()
        self.enrolled = DATA / "enrolled.json"
        protect_directory(DATA)
        if self.uninstall_complete:
            self.enrolled.unlink(missing_ok=True)
            (DATA / "device.dpapi").unlink(missing_ok=True)
            (DATA / "update.exe").unlink(missing_ok=True)
        elif self.enrolled.exists():
            identity = json.loads(self.enrolled.read_text())
            self.load(identity["org_id"], identity["device_id"])

    def load(self, org, device):
        if org != self.config['org_id'] or device != self.config['device_id']:
            raise ValueError('enrollment_binding_mismatch')
        if self.enrolled.exists() and not (DATA / "device.dpapi").exists():
            raise ValueError("device_key_missing")
        signer = DeviceSigner(org, device, device_key(DATA / "device.dpapi"))
        def send(envelope):
            result = post(self.config['endpoint'], {'action': 'consent_device', 'envelope': envelope})
            if envelope['message']['action'] == 'poll':
                from enrollment_config import brand_snapshot
                result = brand_snapshot(result, self.config)
            return result
        self.state = ConsentState(signer, send)

    def snapshot(self):
        if not self.state:
            return dict(online=False, error="not_enrolled", requests=[], connections=[], grants=[], exit=self.uninstall_complete)
        return dict(online=self.state.online, error=self.state.error, organization_name=self.state.organization_name,
                    requests=[r.fields for r in self.state.requests.values()],
                    connections=list(self.state.connections.values()), grants=list(self.state.grants.values()),
                    ending=list(self.state.ending))

    def command(self, command, session, admin):
        action = command.get("action")
        if action == "enroll":
            if not admin or self.enrolled.exists() or self.uninstall_complete:
                raise PermissionError("owner_enrollment_required")
            org, device = identifier(command["org_id"]), identifier(command["device_id"])
            token = command["owner_session"]
            prepared = post(self.config["endpoint"], dict(action="consent_enroll_prepare", org_id=org,
                            device_id=device), token)
            if prepared["org_id"] != org or prepared["device_id"] != device:
                raise ValueError("enrollment_binding_mismatch")
            self.load(org, device)
            result = self.state.send(self.state.signer.enroll(prepared["token"]))
            self.enrolled.write_text(json.dumps(dict(org_id=org, device_id=device)), encoding="utf-8")
            return dict(ok=True)
        if action == "unenroll":
            if admin and self.uninstall_complete:
                if DATA.exists():
                    DATA.rmdir()
                return dict(ok=True, state="unenrolled")
            if not admin or not self.state:
                raise PermissionError("administrator_required")
            result = self.state.send(self.state.signer.sign("unenroll"))
            if result.get("state") == "unenrolled":
                # Persist the broker-confirmed completion before key removal so
                # a service restart between operator commands remains safe.
                from ui import VERSION
                config = dict(self.config, uninstall_complete=True)
                root = Path(config["install_root"])
                for path in (root / "config.json", root / VERSION / "config.json"):
                    path.write_text(json.dumps(config), encoding="utf-8")
                self.enrolled.unlink(missing_ok=True)
                (DATA / "device.dpapi").unlink(missing_ok=True)
                self.state = None
                self.uninstall_complete = True
                # Remove only the service's own known update file and directory.
                (DATA / "update.exe").unlink(missing_ok=True)
                DATA.rmdir()
            return result
        if not active_session(session):
            raise PermissionError("interactive_session_required")
        if action == "snapshot":
            if command.get("unlocked") is True:
                self.last_ui = time.monotonic()
            return self.snapshot()
        if not self.state:
            raise ValueError("not_enrolled")
        if action == "decision":
            if self.maintenance or time.monotonic() - self.last_ui > 3:
                raise PermissionError("interactive_session_required")
            return self.state.decide(command["request_id"], command["approved"], interactive=True,
                    repeat=command.get("repeat", False), scopes=command.get("scopes"),
                    duration=command.get("duration", 2592000), customer_name=command.get("customer_name", ""))
        if action == "end":
            return self.state.end(command["session_id"])
        if action == "revoke":
            return self.state.revoke(command["grant_id"])
        raise ValueError("invalid_command")

    def poll(self):
        delay = 1
        while not self.stop.wait(delay):
            with self.lock:
                if not self.state:
                    continue
                if self.maintenance:
                    continue
                try:
                    if time.monotonic() - self.last_ui <= 3:
                        self.state.poll()
                    else:
                        self.state.online = False
                        self.state.requests.clear()
                    delay = 1
                    # Keep the privacy bar's last state until the broker reports
                    # ended. Loss of the interactive process requests end, never
                    # manufactures termination or an approval.
                    if time.monotonic() - self.last_ui > 4:
                        for connection in self.state.active:
                            self.state.end(connection["id"])
                    if time.monotonic() - self.last_update >= 3600:
                        self.last_update = time.monotonic()
                        from installer import check_update
                        check_update(self.config, bool(self.state.active or self.state.requests), self.prepare_update)
                except Exception:
                    if self.state.error in ("clock_not_synchronized", "message_rejected"):
                        import servicemanager
                        servicemanager.LogWarningMsg("Remote Consent Agent: " + self.state.error)
                    delay = min(delay * 2, 15)

    def prepare_update(self):
        self.maintenance = True
        self.state.online = False
        self.state.requests.clear()
        try:
            result = self.state.send(self.state.signer.sign("pause"))
            if result.get("state") == "paused":
                return True
        except Exception:
            pass
        self.maintenance = False
        return False

    def serve(self):
        threading.Thread(target=self.poll, daemon=True).start()
        while not self.stop.is_set():
            pipe = win32pipe.CreateNamedPipe(PIPE,
                win32pipe.PIPE_ACCESS_DUPLEX | 0x00080000,
                win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | win32pipe.PIPE_WAIT | 0x8,
                1, MAX_MESSAGE, MAX_MESSAGE, 2000, pipe_attributes())
            try:
                try:
                    win32pipe.ConnectNamedPipe(pipe, None)
                except pywintypes.error as error:
                    # A client may connect between CreateNamedPipe and accept.
                    # Windows reports this successful connection as 535.
                    if error.winerror != 535:
                        raise
                raw = win32file.ReadFile(pipe, MAX_MESSAGE)[1]
                session, admin = caller(pipe)
                try:
                    command = json.loads(raw)
                    if command.get("action") not in ("enroll", "unenroll") and not trusted_ui(pipe):
                        raise PermissionError("installed_ui_required")
                    with self.lock:
                        result = self.command(command, session, admin)
                except Exception as error:
                    # Fixed diagnostics only: never serialize exception text,
                    # tokens, owner sessions, arbitrary fields or endpoint URLs.
                    result = {"error": "operation_refused"}
                    import servicemanager
                    servicemanager.LogWarningMsg("Remote consent command refused: " + type(error).__name__)
                win32file.WriteFile(pipe, json.dumps(result, ensure_ascii=False).encode())
                win32file.FlushFileBuffers(pipe)
            except Exception as error:
                import servicemanager
                servicemanager.LogWarningMsg("Remote consent pipe refused: " + type(error).__name__)
            finally:
                win32pipe.DisconnectNamedPipe(pipe)
                pipe.Close()


class ConsentService(win32serviceutil.ServiceFramework):
    _svc_name_ = "RemoteConsentAgent"
    _svc_display_name_ = "Remote Consent Agent consent"
    _svc_description_ = "Device consent key and signed remote-support decisions"

    def __init__(self, args):
        super().__init__(args)
        self.engine = None

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        if self.engine:
            self.engine.stop.set()
        # Wake a blocked pipe accept; it will see stop at the next iteration.
        try:
            from windows_host import ipc
            ipc({"action": "snapshot"})
        except Exception:
            pass

    def SvcDoRun(self):
        import sys
        root = Path(sys.executable).parent if getattr(sys, "frozen", False) else Path(__file__).parent
        self.engine = Engine(json.loads((root / "config.json").read_text(encoding="utf-8-sig")))
        self.engine.serve()
