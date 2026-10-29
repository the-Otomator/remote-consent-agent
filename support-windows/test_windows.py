"""Windows host policy tests, without elevation or a live service installation."""
import io
import os
import sys
import unittest
import threading
import uuid
from pathlib import Path
from unittest.mock import patch

if sys.platform == 'win32':
    from windows_host import https_url, update_allowed, pipe_attributes, publisher_info
    from ui import remote_image


@unittest.skipUnless(sys.platform == 'win32', 'Windows host APIs')
class WindowsHostTests(unittest.TestCase):
    def test_native_service_denials_return_errors_and_accept_next_client(self):
        import service
        import windows_host
        name = r'\\.\pipe\ConsentDenialTest-' + str(uuid.uuid4())
        engine = service.Engine.__new__(service.Engine)
        engine.stop = threading.Event()
        engine.lock = threading.RLock()
        engine.poll = lambda: None
        calls = []
        def deny(*args):
            calls.append(True)
            if len(calls) == 2:
                engine.stop.set()
            raise PermissionError('fixture_denied')
        engine.command = deny
        with patch.object(service, 'PIPE', name), patch.object(windows_host, 'PIPE', name), \
                patch.object(windows_host, 'verify_pipe_server', lambda _: None):
            # Only the SCM binding is fixture-substituted; server pipe creation,
            # caller impersonation, rejection delivery and teardown are native.
            worker = threading.Thread(target=engine.serve, daemon=True)
            worker.start()
            for _ in range(2):
                with self.assertRaisesRegex(ValueError, '^operation_refused$'):
                    windows_host.ipc({'action': 'enroll'})
            worker.join(3)
        self.assertFalse(worker.is_alive())
        self.assertEqual(len(calls), 2)

    def test_real_pipe_caller_identification(self):
        import win32pipe
        import win32file
        import win32con
        import win32api
        import win32security
        from windows_host import caller
        name = r'\\.\pipe\ConsentCallerTest-' + str(uuid.uuid4())
        server = win32pipe.CreateNamedPipe(name, win32pipe.PIPE_ACCESS_DUPLEX,
            win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | win32pipe.PIPE_WAIT,
            1, 4096, 4096, 1000, None)
        received = []
        def accept():
            try:
                win32pipe.ConnectNamedPipe(server, None)
                win32file.ReadFile(server, 4096)
                received.append(caller(server))
            finally:
                server.Close()
        worker = threading.Thread(target=accept, daemon=True)
        worker.start()
        client = win32file.CreateFile(name, win32con.GENERIC_READ | win32con.GENERIC_WRITE,
            0, None, win32con.OPEN_EXISTING, 0x00110000, None)
        try:
            win32file.WriteFile(client, b'fixture')
            worker.join(3)
        finally:
            client.Close()
        token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
        expected = win32security.GetTokenInformation(token, win32security.TokenSessionId)
        self.assertFalse(worker.is_alive())
        self.assertEqual(len(received), 1)
        self.assertEqual(received[0][0], expected)
        self.assertIsInstance(received[0][1], bool)

    def test_installer_rejects_user_writable_service_location(self):
        from installer import program_files_root, safe_root
        root = program_files_root()
        self.assertEqual(safe_root(root / 'RemoteConsentAgentTest'), root / 'RemoteConsentAgentTest')
        with self.assertRaises(ValueError):
            safe_root(Path(r'C:\Users\Public\RemoteConsentAgentTest'))

    def test_real_authenticode_inspection_with_powershell7_module_path(self):
        import win32api
        executable = Path(win32api.GetWindowsDirectory()) / 'System32' / 'cmd.exe'
        with patch.dict(os.environ, {'PSModulePath': r'C:\Program Files\PowerShell\7\Modules'}):
            info = publisher_info(executable)
        self.assertRegex(info['thumbprint'], r'^[A-Fa-f0-9]{40}$')
        self.assertTrue(info['version'])

    def test_endpoint_rejects_plaintext_credentials_queries_fragments(self):
        for url in ('http://example.test', 'file:///test', 'https://user:pass@example.test',
                    'https://example.test/path?token=secret', 'https://example.test/#fragment'):
            with self.assertRaises(ValueError):
                https_url(url)
        self.assertEqual(https_url('https://example.test/functions/v1/support-remote-access'),
                         'https://example.test/functions/v1/support-remote-access')

    def test_update_publisher_versions_and_busy_gate(self):
        with patch('windows_host.publisher_info', return_value=dict(thumbprint='A'*40, version='1.0.0.0')) as inspect:
            self.assertFalse(update_allowed(Path('test.exe'), 'A'*40, '0.9.0', True))
            inspect.assert_not_called()
            self.assertTrue(update_allowed(Path('test.exe'), 'A'*40, '0.9.0', False))
            self.assertFalse(update_allowed(Path('test.exe'), 'A'*40, '1.0.0', False))
            self.assertFalse(update_allowed(Path('test.exe'), 'A'*40, '2.0', False))
            self.assertFalse(update_allowed(Path('test.exe'), 'B'*40, '0.9.0', False))
        with patch('windows_host.publisher_info', side_effect=ValueError('signature_refused')):
            self.assertFalse(update_allowed(Path('unsigned.exe'), 'A'*40, '0.9.0', False))

    def test_native_pipe_security_descriptor(self):
        import win32security
        attributes = pipe_attributes()
        descriptor = win32security.ConvertSecurityDescriptorToStringSecurityDescriptor(
            attributes.SECURITY_DESCRIPTOR, 1, win32security.DACL_SECURITY_INFORMATION)
        self.assertIn('SY', descriptor)
        self.assertIn('IU', descriptor)
        self.assertNotIn(';;;WD', descriptor)
        self.assertNotIn(';;;AN', descriptor)

    def test_pipe_squatter_receives_no_owner_credential(self):
        import win32pipe
        import win32file
        import windows_host
        name = r'\\.\pipe\JumpStartConsentFixture-' + str(uuid.uuid4())
        server = win32pipe.CreateNamedPipe(name, win32pipe.PIPE_ACCESS_DUPLEX,
            win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | win32pipe.PIPE_WAIT,
            1, 4096, 4096, 1000, None)
        received = []
        def accept():
            try:
                win32pipe.ConnectNamedPipe(server, None)
                received.append(win32file.ReadFile(server, 4096)[1])
            except Exception:
                pass
            finally:
                server.Close()
        worker = threading.Thread(target=accept, daemon=True)
        worker.start()
        with patch.object(windows_host, 'PIPE', name):
            with self.assertRaises(Exception):
                windows_host.ipc(dict(action='enroll', owner_session='synthetic-owner-capability'))
        worker.join(3)
        self.assertFalse(worker.is_alive())
        self.assertFalse(received)

    def test_remote_images_refuse_unsafe_failed_huge_or_html(self):
        for url in ('http://example.test/image.png', 'file:///test', 'javascript:alert(1)',
                    'https://user:pass@example.test/photo', None):
            self.assertIsNone(remote_image(url))
        class Response:
            def __init__(self, value): self.value = io.BytesIO(value)
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read1(self, limit): return self.value.read(limit)
        for content in (b'<script>alert(1)</script>', b'A'*(1024*1024+1)):
            with patch('ui.build_opener') as opener:
                opener.return_value.open.return_value = Response(content)
                self.assertIsNone(remote_image('https://example.test/image'))
        with patch('ui.build_opener') as opener:
            opener.return_value.open.side_effect = TimeoutError()
            self.assertIsNone(remote_image('https://example.test/image'))
        from PIL import Image
        image = Image.new('RGB', (80,80), 'blue')
        output = io.BytesIO()
        image.save(output, format='PNG')
        with patch('ui.build_opener') as opener:
            opener.return_value.open.return_value = Response(output.getvalue())
            self.assertEqual(remote_image('https://example.test/image').size, (40,40))


if __name__ == '__main__':
    unittest.main(verbosity=2)
