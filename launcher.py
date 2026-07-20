from __future__ import annotations

import os
import sys
import subprocess
import threading
import time
import webbrowser

APP_NAME = "Detector - Phishing URL Analyzer"
APP_URL = "http://127.0.0.1:5000"
PORT = 5000


def get_project_dir() -> str:
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def find_python(project_dir: str) -> str:
    venv_python = os.path.join(project_dir, "venv", "Scripts", "python.exe")
    if os.path.isfile(venv_python):
        return venv_python
    return sys.executable


def ensure_venv(project_dir: str) -> str:
    venv_dir = os.path.join(project_dir, "venv")
    venv_python = os.path.join(venv_dir, "Scripts", "python.exe")
    if not os.path.isfile(venv_python):
        subprocess.run(
            [sys.executable, "-m", "venv", venv_dir],
            cwd=project_dir,
            check=True,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    return venv_python


def install_deps(python_path: str, project_dir: str) -> None:
    req_file = os.path.join(project_dir, "requirements.txt")
    if not os.path.isfile(req_file):
        return
    result = subprocess.run(
        [python_path, "-m", "pip", "install", "-r", req_file, "-q"],
        cwd=project_dir,
        capture_output=True,
        text=True,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if result.returncode != 0 and result.stderr:
        pass  # non-critical


def ensure_dirs(project_dir: str) -> None:
    for d in ("results", "instance"):
        path = os.path.join(project_dir, d)
        if not os.path.isdir(path):
            os.makedirs(path, exist_ok=True)


def open_browser_delayed() -> None:
    time.sleep(3)
    webbrowser.open(APP_URL)


def _run_flask_standalone(basedir: str) -> None:
    os.chdir(basedir)
    ensure_dirs(basedir)
    env_path = os.path.join(basedir, ".env")
    if not os.path.isfile(env_path) and getattr(sys, "frozen", False):
        import shutil
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            src = os.path.join(meipass, ".env")
            if os.path.isfile(src):
                shutil.copy2(src, env_path)
    threading.Thread(target=open_browser_delayed, daemon=True).start()
    from app import create_app
    application = create_app()
    application.run(host="0.0.0.0", port=PORT, debug=False, use_reloader=False)


def run_server(python_path: str, project_dir: str) -> None:
    subprocess.run(
        [python_path, "run.py"],
        cwd=project_dir,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )


def main() -> None:
    if getattr(sys, "frozen", False):
        _run_flask_standalone(get_project_dir())
        return

    project_dir = get_project_dir()
    os.chdir(project_dir)
    python_path = ensure_venv(project_dir)
    install_deps(python_path, project_dir)
    ensure_dirs(project_dir)
    threading.Thread(target=open_browser_delayed, daemon=True).start()
    try:
        run_server(python_path, project_dir)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        input(f"\n  Error: {e}\n  Press Enter to exit...")


if __name__ == "__main__":
    main()
