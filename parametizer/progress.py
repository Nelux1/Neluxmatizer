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

def update_progress(current, total):
    global spinner_index
    with spinner_lock:
        spinner_char = spinner[spinner_index % len(spinner)]
        spinner_index += 1
        #print(f'\r \033[1;36mTesting:\033[0m {spinner_char} {current}/{total} {spinner_char}', end='', flush=True)
        sys.stdout.write(ansi.clear_line())
        sys.stdout.write(f'\r \033[1;36mTesting:\033[0m {spinner_char} {current}/{total} {spinner_char}')
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