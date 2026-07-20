# -*- mode: python ; coding: utf-8 -*-

import sys
sys.setrecursionlimit(5000)

a = Analysis(
    ['launcher.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('.env', '.'),
        ('requirements.txt', '.'),
    ],
    hiddenimports=[
        'app', 'app.config', 'app.extensions', 'app.models',
        'app.phishing', 'app.phishing.heuristics', 'app.phishing.services',
        'app.phishing.virustotal', 'app.phishing.urlscan',
        'app.phishing.abuseipdb', 'app.phishing.safebrowsing',
        'app.phishing.routes',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'tkinter', 'test', 'unittest', 'setuptools',
        'pip', 'pygame',
    ],
    noarchive=False,
    optimize=0,
)

a.datas += Tree('app', prefix='app')

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='Detector',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
