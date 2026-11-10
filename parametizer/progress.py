import time, sys,threading
from colorama import init, Fore, Style,Cursor,ansi

init()

def fmt_line(color_code: str, prefix_to_colon: str, body: str) -> str:
    """
    prefix_to_colon: etiqueta hasta e incluyendo ':' en el color (ej. 1;36 cian, 1;32 verde).
    body: texto después de ':' en blanco negrita.
    """
    return f"\033[{color_code}m{prefix_to_colon}\033[0m \033[1;37m{body}\033[0m"


spinner = ['|', '/', '-', '\\']
spinner_index = 0
spinner_lock = threading.Lock()
progress_label = "Testing"
progress_workers = None

def start_scan_progress(kind, endpoints, payloads, total, workers=None):
    """Una línea con el total real de pruebas y el spinner de esa fase."""
    global progress_label, progress_workers, spinner_index
    if payloads:
        detail = f"{total}  ({endpoints} endpoints × {payloads} payloads)"
    else:
        detail = f"{total}  ({endpoints} endpoints)"
    sys.stdout.write(fmt_line("1;36", f"[+] {kind} tests:", detail) + "\n")
    sys.stdout.flush()
    with spinner_lock:
        progress_label = f"Testing {kind}"
        progress_workers = workers if workers and workers > 0 else None
        spinner_index = 0

def update_progress(current, total):
    global spinner_index
    with spinner_lock:
        spinner_char = spinner[spinner_index % len(spinner)]
        spinner_index += 1
        workers = f"  ×{progress_workers}" if progress_workers else ""
        sys.stdout.write(ansi.clear_line())
        sys.stdout.write(
            f'\r \033[1;36m{progress_label}:\033[0m {spinner_char} {current}/{total}{workers}'
        )
        sys.stdout.flush()

def print_vulnerability(message):
    """
    Función para imprimir vulnerabilidades de manera limpia, asegurando
    que siempre haya un salto de línea apropiado y que no interfiera
    con la barra de progreso
    """
    with spinner_lock:
        # Limpiar la línea actual completamente
        sys.stdout.write('\r' + ansi.clear_line())
        sys.stdout.flush()
        
        # Imprimir la vulnerabilidad sin salto de línea automático
        sys.stdout.write(message + '\n')
        sys.stdout.flush()