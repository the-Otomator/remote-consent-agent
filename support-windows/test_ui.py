"""Native widgets drive the real signing/consent state with synthetic snapshots."""
import sys
import unittest
import uuid
from unittest.mock import patch
import test_protocol


@unittest.skipUnless(sys.platform == 'win32', 'Windows native UI')
class NativeUITests(unittest.TestCase):
    def setUp(self):
        import ui
        import tkinter as tk
        self.ui_module, self.tk = ui, tk
        self.fixture = test_protocol.ProtocolTests(methodName='runTest')
        self.fixture.setUp()
        self.addCleanup(patch.stopall)
        patch('ui.input_desktop_unlocked', return_value=True).start()
        patch('ui.user_name', return_value='Example user').start()
        patch('ui.time.time', lambda: self.fixture.now).start()
        self.ui = ui.CustomerUI('en', gallery=True)
        self.ui.snapshot['online'] = True
        self.addCleanup(self.close)
        def dispatch(command):
            action = command['action']
            if action == 'decision':
                self.fixture.state.decide(command['request_id'], command['approved'], interactive=True,
                    repeat=command.get('repeat', False), scopes=command.get('scopes'),
                    duration=command.get('duration', 2592000), customer_name=command.get('customer_name', ''))
            elif action == 'end': self.fixture.state.end(command['session_id'])
            elif action == 'revoke': self.fixture.state.revoke(command['grant_id'])
        self.ui.dispatch = dispatch

    def close(self):
        for timer in self.ui.root.tk.call('after', 'info'):
            self.ui.root.after_cancel(timer)
        self.ui.root.destroy()

    def buttons(self, window):
        result = []
        def visit(widget):
            if isinstance(widget, self.tk.Button): result.append(widget)
            for child in widget.winfo_children(): visit(child)
        visit(window)
        return result

    def click(self, window, text):
        next(b for b in self.buttons(window) if b.cget('text') == text).invoke()

    def test_click_signs_bound_approval_default_repeat_false(self):
        self.ui.request_window(self.fixture.raw)
        self.assertFalse(self.ui.repeat.get())
        self.ui.window.update()
        self.assertTrue(self.ui.window.attributes('-topmost'))
        self.click(self.ui.window, 'Approve')
        message = self.fixture.sent[-1]['message']
        self.assertTrue(message['approved'])
        self.assertFalse(message['repeat'])
        self.assertEqual(message['technician_auth_id'], self.fixture.tech)

    def test_window_close_denies(self):
        self.ui.request_window(self.fixture.raw)
        self.ui.window.tk.call(self.ui.window.protocol('WM_DELETE_WINDOW'))
        self.assertFalse(self.fixture.sent[-1]['message']['approved'])

    def test_keyboard_does_not_approve(self):
        self.ui.request_window(self.fixture.raw)
        button = next(b for b in self.buttons(self.ui.window) if b.cget('text') == 'Approve')
        self.assertEqual(str(button.cget('takefocus')), '0')
        button.focus_force()
        button.event_generate('<KeyPress-Return>')
        button.event_generate('<KeyPress-space>')
        self.ui.window.update()
        self.assertEqual(self.fixture.sent, [])

    def test_standing_grant_and_tray_revoke(self):
        raw = dict(self.fixture.raw, purpose='standing', scopes=['desktop', 'files'])
        self.fixture.state.ingest(dict(self.fixture.snapshot, requests=[raw]))
        self.ui.request_window(raw)
        self.ui.scopes['files'].set(False)
        self.ui.duration.set('forever')
        self.click(self.ui.window, 'Approve automatic connection')
        message = self.fixture.sent[-1]['message']
        self.assertEqual(message['scopes'], ['desktop'])
        self.assertIsNone(message['duration'])
        grant = str(uuid.uuid4())
        self.fixture.state.grants[grant] = dict(id=grant)
        self.ui.snapshot = dict(online=True, requests=[], connections=[], grants=[dict(id=grant, scopes=['desktop'], expires_at=None)])
        self.ui.tray_window()
        self.click(self.ui.tray, 'Revoke automatic connection')
        self.assertEqual(self.fixture.sent[-1]['message']['action'], 'revoke')

    def test_hebrew_and_english_all_connection_actions_visible(self):
        for lang in ('he', 'en'):
            self.ui.lang = lang
            self.ui.words = self.ui_module.HE if lang == 'he' else self.ui_module.EN
            self.ui.rtl = lang == 'he'
            for transport in ('desktop', 'terminal', 'files'):
                self.ui.request_window(dict(self.fixture.raw, transport=transport, technician_name='Example technician'))
                self.ui.window.update()
                for button in self.buttons(self.ui.window):
                    self.assertGreaterEqual(button.winfo_width(), button.winfo_reqwidth())
                    self.assertLessEqual(button.winfo_rooty() + button.winfo_height(), self.ui.window.winfo_rooty() + self.ui.window.winfo_height())


if __name__ == '__main__': unittest.main()
