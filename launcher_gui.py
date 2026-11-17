"""Native Windows launcher for the offline HashLab coordinator."""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path


WORDLISTS = (
    "private_data/wordlists/seeds.txt",
    "private_data/wordlists/rockyou.txt",
    "private_data/wordlists/xato_top10m.txt",
)
RULES = (
    "tools/hashcat-7.1.2/rules/best66.rule",
    "reglas_ciber.rule",
)
PYTHON = "tools/python/python.exe"
HASHCAT = "tools/hashcat-7.1.2/hashcat.exe"
JOHN = "tools/john-1.9.0-jumbo-1-win64/run/john.exe"
HEX64 = re.compile(r"[0-9a-fA-F]{64}\Z")


def validated_targets(root: Path) -> list[dict[str, str]]:
    """Check the manifest, original hash files, and all bundled components."""
    data_dir = (root / "private_data").resolve()
    manifest = data_dir / "targets.json"
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError("Falta el archivo de hashes del paquete.") from exc
    entries = data.get("targets") if isinstance(data, dict) else None
    if not isinstance(entries, list) or len(entries) != 3:
        raise ValueError("El paquete debe contener exactamente tres hashes.")
    names: set[str] = set()
    digests: set[str] = set()
    targets = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("Hay un objetivo sin formato válido.")
        name, digest, source = entry.get("name"), entry.get("hash"), entry.get("source")
        if not isinstance(name, str) or not name or "\n" in name or name in names:
            raise ValueError("Hay un nombre de reto inválido o repetido.")
        if not isinstance(digest, str) or not HEX64.fullmatch(digest) or digest.lower() in digests:
            raise ValueError(f"El hash de {name} es inválido o repetido.")
        if not isinstance(source, str) or not source:
            raise ValueError(f"Falta el archivo de referencia de {name}.")
        source_path = (data_dir / source).resolve()
        if not source_path.is_relative_to(data_dir):
            raise ValueError(f"Ruta de referencia inválida para {name}.")
        try:
            actual = source_path.read_text(encoding="ascii").strip()
        except (OSError, UnicodeError) as exc:
            raise ValueError(f"No se pudo leer el hash de {name}.") from exc
        if actual != digest:
            raise ValueError(f"El hash de {name} no coincide con su archivo de referencia.")
        names.add(name)
        digests.add(digest.lower())
        targets.append({"name": name, "hash": digest.lower()})
    for relative in (
        PYTHON, "tools/python/pythonw.exe", HASHCAT, JOHN,
        "cluster_core.py", *WORDLISTS, *RULES,
        "private_data/screenshots/Gorillaz.png",
        "private_data/screenshots/Morat.png",
        "private_data/screenshots/Final_Copa_Sudamericana.png",
    ):
        if not (root / relative).is_file():
            raise ValueError(f"Falta un componente del paquete: {relative}")
    return targets


def build_command(root: Path, computer: int, engine: str) -> list[str]:
    if not 1 <= computer <= 20 or engine not in ("hashcat", "john"):
        raise ValueError("Selecciona un computador del 1 al 20 y un motor válido.")
    command = [
        str(root / PYTHON), str(root / "cluster_core.py"), "run",
        "--targets", str(root / "private_data/targets.json"),
        "--computer", str(computer), "--total", "20",
        "--state-dir", str(root / "state"),
        "--engine", engine,
    ]
    if engine == "hashcat":
        command.extend(("--hashcat", str(root / HASHCAT), "--masks"))
    else:
        command.extend(("--john", str(root / JOHN)))
    for wordlist in WORDLISTS:
        command.extend(("--wordlist", str(root / wordlist)))
    for rule in RULES:
        command.extend(("--rule", str(root / rule)))
    return command


def tail_lines(path: Path, limit: int = 35) -> list[str]:
    if not path.is_file():
        return []
    with path.open("rb") as source:
        source.seek(0, 2)
        source.seek(max(0, source.tell() - 65536))
        text = source.read().decode("utf-8", errors="replace")
    return text.splitlines()[-limit:]


def verified_results(node_dir: Path, targets: list[dict[str, str]]) -> list[dict[str, str]]:
    path = node_dir / "results.json"
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    known = {target["hash"]: target["name"] for target in targets}
    verified = {}
    if not isinstance(data, dict) or not isinstance(data.get("found"), list):
        return []
    for item in data["found"]:
        if not isinstance(item, dict):
            continue
        try:
            digest = item["hash"].lower()
            plaintext = bytes.fromhex(item["plaintext_hex"])
        except (KeyError, AttributeError, ValueError, TypeError):
            continue
        if digest not in known or hashlib.sha256(plaintext).hexdigest() != digest:
            continue
        verified[digest] = {
            "name": known[digest],
            "flag": f"FLAG{{{hashlib.md5(plaintext).hexdigest()}}}",
        }
    return list(verified.values())


def run_windows_gui(root: Path) -> int:
    if os.name != "nt":
        raise RuntimeError("This graphical launcher requires Windows.")
    from ctypes import wintypes

    user32 = ctypes.windll.user32
    kernel32 = ctypes.windll.kernel32
    gdi32 = ctypes.windll.gdi32
    WNDPROC = ctypes.WINFUNCTYPE(ctypes.c_ssize_t, ctypes.c_void_p, ctypes.c_uint,
                                 ctypes.c_size_t, ctypes.c_ssize_t)

    class WNDCLASSW(ctypes.Structure):
        _fields_ = [
            ("style", ctypes.c_uint), ("lpfnWndProc", WNDPROC),
            ("cbClsExtra", ctypes.c_int), ("cbWndExtra", ctypes.c_int),
            ("hInstance", ctypes.c_void_p), ("hIcon", ctypes.c_void_p),
            ("hCursor", ctypes.c_void_p), ("hbrBackground", ctypes.c_void_p),
            ("lpszMenuName", ctypes.c_wchar_p), ("lpszClassName", ctypes.c_wchar_p),
        ]

    user32.RegisterClassW.argtypes = [ctypes.POINTER(WNDCLASSW)]
    user32.RegisterClassW.restype = ctypes.c_ushort
    user32.CreateWindowExW.argtypes = [
        ctypes.c_ulong, ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_ulong,
        ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
    ]
    user32.CreateWindowExW.restype = ctypes.c_void_p
    user32.DefWindowProcW.argtypes = [ctypes.c_void_p, ctypes.c_uint,
                                     ctypes.c_size_t, ctypes.c_ssize_t]
    user32.DefWindowProcW.restype = ctypes.c_ssize_t
    user32.SendMessageW.argtypes = [ctypes.c_void_p, ctypes.c_uint,
                                    ctypes.c_size_t, ctypes.c_ssize_t]
    user32.SendMessageW.restype = ctypes.c_ssize_t
    user32.SetWindowTextW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p]
    user32.EnableWindow.argtypes = [ctypes.c_void_p, ctypes.c_int]
    user32.MessageBoxW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p,
                                   ctypes.c_wchar_p, ctypes.c_uint]
    user32.LoadCursorW.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    user32.LoadCursorW.restype = ctypes.c_void_p
    user32.SetTimer.argtypes = [ctypes.c_void_p, ctypes.c_size_t,
                                ctypes.c_uint, ctypes.c_void_p]
    user32.KillTimer.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    user32.DestroyWindow.argtypes = [ctypes.c_void_p]
    user32.GetMessageW.argtypes = [ctypes.POINTER(wintypes.MSG), ctypes.c_void_p,
                                   ctypes.c_uint, ctypes.c_uint]
    user32.TranslateMessage.argtypes = [ctypes.POINTER(wintypes.MSG)]
    user32.DispatchMessageW.argtypes = [ctypes.POINTER(wintypes.MSG)]
    kernel32.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]
    kernel32.GetModuleHandleW.restype = ctypes.c_void_p
    gdi32.GetStockObject.argtypes = [ctypes.c_int]
    gdi32.GetStockObject.restype = ctypes.c_void_p

    WS_VISIBLE, WS_CHILD, WS_TABSTOP = 0x10000000, 0x40000000, 0x00010000
    WS_BORDER, WS_VSCROLL = 0x00800000, 0x00200000
    WS_CAPTION, WS_SYSMENU, WS_MINIMIZEBOX = 0x00C00000, 0x00080000, 0x00020000
    ES_MULTILINE, ES_READONLY, ES_AUTOVSCROLL = 0x0004, 0x0800, 0x0040
    CBS_DROPDOWNLIST, WS_EX_CLIENTEDGE = 0x0003, 0x00000200
    WM_CREATE, WM_DESTROY, WM_CLOSE, WM_COMMAND, WM_TIMER = 1, 2, 16, 273, 275
    WM_SETFONT, CB_ADDSTRING, CB_GETCURSEL, CB_SETCURSEL = 48, 323, 327, 334
    BN_CLICKED, IDYES, MB_YESNO, MB_ICONQUESTION = 0, 6, 4, 32
    ID_START, ID_STOP, ID_SCREENSHOTS, ID_NODE, ID_ENGINE = 101, 102, 103, 201, 202

    try:
        targets = validated_targets(root)
    except ValueError as exc:
        user32.MessageBoxW(None, str(exc), "HashLab: paquete incompleto", 0x10)
        return 2

    state: dict[str, object] = {"process": None, "node_dir": None, "finished": False}
    handles: dict[str, int] = {}
    hinstance = kernel32.GetModuleHandleW(None)
    font = gdi32.GetStockObject(17)
    mono = gdi32.GetStockObject(11)

    def control(hwnd, kind, text, style, x, y, width, height, control_id=0, fixed=False):
        child = user32.CreateWindowExW(
            WS_EX_CLIENTEDGE if kind == "EDIT" else 0,
            kind, text, WS_CHILD | WS_VISIBLE | style, x, y, width, height,
            hwnd, control_id, hinstance, None,
        )
        if not child:
            raise ctypes.WinError()
        user32.SendMessageW(child, WM_SETFONT, mono if fixed else font, 1)
        return child

    def add_choice(combo, label):
        buffer = ctypes.create_unicode_buffer(label)
        user32.SendMessageW(combo, CB_ADDSTRING, 0, ctypes.cast(buffer, ctypes.c_void_p).value)

    def set_text(key, text):
        user32.SetWindowTextW(handles[key], text)

    def update_progress():
        node_dir = state["node_dir"]
        process = state["process"]
        if not node_dir or process is None:
            return
        display = tail_lines(node_dir / "run.log", 24)
        logs = sorted(node_dir.glob("hashlab_*.log"), key=lambda p: p.stat().st_mtime, reverse=True)
        if logs:
            display.extend(("", "Salida del motor:", *tail_lines(logs[0], 25)))
        if process.poll() is not None and not state["finished"]:
            state["finished"] = True
            records = verified_results(node_dir, targets)
            if records:
                display.extend(("", "Resultados verificados:"))
                display.extend(f"{item['name']}: {item['flag']}" for item in records)
            else:
                display.extend(("", "Sin resultados verificados en este computador."))
            if process.returncode != 0:
                display.extend(("", "Detalle del error:", *tail_lines(node_dir / "launcher_error.log", 8)))
            set_text("status", f"Finalizó con código {process.returncode}.")
            user32.EnableWindow(handles["start"], 1)
            user32.EnableWindow(handles["stop"], 0)
            user32.EnableWindow(handles["node"], 1)
            user32.EnableWindow(handles["engine"], 1)
            user32.KillTimer(handles["window"], 1)
        set_text("log", "\r\n".join(display))

    def start_work(hwnd):
        try:
            validated_targets(root)
            index = user32.SendMessageW(handles["node"], CB_GETCURSEL, 0, 0)
            computer = int(index) + 1
            engine_index = user32.SendMessageW(handles["engine"], CB_GETCURSEL, 0, 0)
            engine = "john" if engine_index == 1 else "hashcat"
            command = build_command(root, computer, engine)
        except (ValueError, OSError) as exc:
            user32.MessageBoxW(hwnd, str(exc), "HashLab: paquete incompleto", 0x10)
            return
        answer = user32.MessageBoxW(
            hwnd,
            f"¿Confirmas los tres hashes mostrados y que este es el computador {computer} de 20?",
            "Confirmar objetivos", MB_YESNO | MB_ICONQUESTION,
        )
        if answer != IDYES:
            return
        node_dir = root / "state" / f"node-{computer:02d}"
        node_dir.mkdir(parents=True, exist_ok=True)
        (node_dir / "stop.flag").unlink(missing_ok=True)
        try:
            with (node_dir / "launcher_error.log").open("wb") as output:
                process = subprocess.Popen(
                    command, cwd=root, stdin=subprocess.DEVNULL,
                    stdout=output, stderr=subprocess.STDOUT,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
        except OSError as exc:
            user32.MessageBoxW(hwnd, str(exc), "HashLab: no se pudo iniciar", 0x10)
            return
        state.update(process=process, node_dir=node_dir, engine=engine, finished=False)
        user32.EnableWindow(handles["start"], 0)
        user32.EnableWindow(handles["stop"], 1)
        user32.EnableWindow(handles["node"], 0)
        user32.EnableWindow(handles["engine"], 0)
        set_text("status", f"Computador {computer}: ejecutando {engine}.")
        user32.SetTimer(hwnd, 1, 1500, None)

    def wndproc(hwnd, message, wparam, lparam):
        try:
            if message == WM_CREATE:
                handles["window"] = hwnd
                control(hwnd, "STATIC", "Bienvenido a HashLab", 0, 24, 18, 1030, 28)
                control(hwnd, "STATIC",
                        "Confirma los tres hashes, elige un número diferente por computador y comienza.",
                        0, 24, 54, 1030, 25)
                handles["targets"] = control(
                    hwnd, "EDIT",
                    "\r\n".join(f"{target['name']}: {target['hash']}" for target in targets),
                    WS_BORDER | ES_MULTILINE | ES_READONLY | WS_VSCROLL,
                    24, 88, 1020, 145, fixed=True,
                )
                control(hwnd, "STATIC", "3 hashes cotejados. Modo provisional: SHA-256 crudo.",
                        0, 24, 244, 1010, 25)
                control(hwnd, "STATIC", "Este es el computador:", 0, 24, 287, 200, 27)
                handles["node"] = control(
                    hwnd, "COMBOBOX", "", CBS_DROPDOWNLIST | WS_TABSTOP,
                    230, 282, 180, 500, ID_NODE,
                )
                for number in range(1, 21):
                    add_choice(handles["node"], f"Computador {number}")
                user32.SendMessageW(handles["node"], CB_SETCURSEL, 0, 0)
                control(hwnd, "STATIC", "Motor:", 0, 450, 287, 65, 27)
                handles["engine"] = control(
                    hwnd, "COMBOBOX", "", CBS_DROPDOWNLIST | WS_TABSTOP,
                    515, 282, 240, 110, ID_ENGINE,
                )
                add_choice(handles["engine"], "Hashcat (GPU)")
                add_choice(handles["engine"], "John (CPU, diccionarios)")
                user32.SendMessageW(handles["engine"], CB_SETCURSEL, 0, 0)
                control(hwnd, "STATIC", "No repitas el número en otro equipo.",
                        0, 24, 322, 820, 24)
                handles["start"] = control(
                    hwnd, "BUTTON", "Confirmar e iniciar", WS_TABSTOP,
                    24, 365, 190, 36, ID_START,
                )
                handles["stop"] = control(
                    hwnd, "BUTTON", "Detener", WS_TABSTOP,
                    226, 365, 210, 36, ID_STOP,
                )
                user32.EnableWindow(handles["stop"], 0)
                handles["screenshots"] = control(
                    hwnd, "BUTTON", "Ver capturas", WS_TABSTOP,
                    450, 365, 150, 36, ID_SCREENSHOTS,
                )
                handles["status"] = control(
                    hwnd, "STATIC", "Listo para comenzar.", 0, 24, 415, 1010, 26,
                )
                control(hwnd, "STATIC", "Progreso y resultados verificados",
                        0, 24, 449, 1010, 26)
                handles["log"] = control(
                    hwnd, "EDIT", "", WS_BORDER | ES_MULTILINE | ES_READONLY |
                    WS_VSCROLL | ES_AUTOVSCROLL, 24, 477, 1020, 180, fixed=True,
                )
                return 0
            if message == WM_COMMAND:
                control_id = int(wparam) & 0xFFFF
                notification = int(wparam) >> 16
                if notification == BN_CLICKED and control_id == ID_START:
                    start_work(hwnd)
                    return 0
                if notification == BN_CLICKED and control_id == ID_STOP:
                    node_dir = state["node_dir"]
                    process = state["process"]
                    if node_dir and process is not None and process.poll() is None:
                        (node_dir / "stop.flag").touch()
                        status = ("Guardando punto de control..." if state["engine"] == "hashcat"
                                  else "Deteniendo John; la etapa actual puede repetirse...")
                        set_text("status", status)
                        user32.EnableWindow(handles["stop"], 0)
                    return 0
                if notification == BN_CLICKED and control_id == ID_SCREENSHOTS:
                    os.startfile(root / "private_data/screenshots")
                    return 0
            if message == WM_TIMER:
                update_progress()
                return 0
            if message == WM_CLOSE:
                process = state["process"]
                if process is not None and process.poll() is None:
                    user32.MessageBoxW(hwnd, "Detén primero el trabajo para conservar el avance.",
                                       "Trabajo en curso", 0x30)
                    return 0
                user32.DestroyWindow(hwnd)
                return 0
            if message == WM_DESTROY:
                user32.PostQuitMessage(0)
                return 0
        except Exception as exc:
            user32.MessageBoxW(hwnd, str(exc), "HashLab: error", 0x10)
        return user32.DefWindowProcW(hwnd, message, wparam, lparam)

    callback = WNDPROC(wndproc)
    class_name = "HashLabOfflineWindow"
    window_class = WNDCLASSW()
    window_class.lpfnWndProc = callback
    window_class.hInstance = hinstance
    window_class.hCursor = user32.LoadCursorW(None, ctypes.c_void_p(32512))
    window_class.hbrBackground = 6
    window_class.lpszClassName = class_name
    if not user32.RegisterClassW(ctypes.byref(window_class)):
        raise ctypes.WinError()
    window = user32.CreateWindowExW(
        0, class_name, "HashLab | Laboratorio CTF",
        WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_VISIBLE,
        100, 100, 1080, 710, None, None, hinstance, None,
    )
    if not window:
        raise ctypes.WinError()
    message = wintypes.MSG()
    while user32.GetMessageW(ctypes.byref(message), None, 0, 0) > 0:
        user32.TranslateMessage(ctypes.byref(message))
        user32.DispatchMessageW(ctypes.byref(message))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(run_windows_gui(Path(__file__).resolve().parent))
    except Exception as error:
        if os.name == "nt":
            ctypes.windll.user32.MessageBoxW(None, str(error), "HashLab: error", 0x10)
        raise SystemExit(1)
