# Third-party notices

The executable bundles Python (PSF license), Tcl/Tk (Tcl/Tk license),
cryptography (Apache-2.0 OR BSD-3-Clause, with its dependency notices),
pywin32 (PSF license), Pillow (MIT-CMU), and the PyInstaller bootloader
(GPL with the bootloader exception permitting bundled applications).
It also includes their runtime dependencies; none is proprietary.

The tag workflow extracts installed distribution license/NOTICE files into
`THIRD-PARTY-LICENSES` and packages them alongside the executable and Python/Tcl
runtime notices. Review the complete generated inventory for every release.
These upstream licenses continue to apply to bundled dependencies; the project's
own source is MIT. No upstream dependency is submitted for separate signing.
