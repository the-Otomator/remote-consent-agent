"""Executed by test-signing.ps1 with a real, temporary local test certificate."""
import sys
from pathlib import Path
from windows_host import update_allowed, publisher_info
from ui import VERSION


if __name__ == '__main__':
    signed, unsigned, publisher = sys.argv[1:]
    print('Test certificate inspection:', publisher_info(Path(signed)), flush=True)
    assert update_allowed(Path(signed), publisher, '0.9.0.0', False)
    assert not update_allowed(Path(signed), publisher, '0.9.0.0', True)
    assert not update_allowed(Path(signed), publisher, VERSION + '.0', False)
    assert not update_allowed(Path(signed), publisher, VERSION, False)
    assert not update_allowed(Path(signed), publisher, '2.0.0.0', False)
    assert not update_allowed(Path(signed), '0' * 40, '0.9.0.0', False)
    assert not update_allowed(Path(unsigned), publisher, '0.9.0.0', False)
    print('PASS: newer trusted publisher accepted; busy, unsigned, other publisher, same/older refused')
