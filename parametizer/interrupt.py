import sys
import os
import signal
import threading
import concurrent.futures
from colorama import Back, Fore, Cursor, init

init()

# Variable global para controlar la interrupción
interrupt_requested = False
interrupt_lock = threading.Lock()

def signal_handler(signal, frame):
    """Manejador de señal mejorado que funciona con threads"""
    global interrupt_requested
    
    with interrupt_lock:
        if interrupt_requested:
            # Segunda interrupción - salida forzada
            sys.stdout.write(f"\n{Fore.RED}\033[1m[!] Forcing exit...{Fore.RESET}\n")
            sys.stdout.flush()
            os._exit(1)
        else:
            # Primera interrupción - solicitar parada elegante
            interrupt_requested = True
            sys.stdout.write(f"\n{Fore.RED}\033[1m[!] Scan interrupted by user{Fore.RESET}\n")
            sys.stdout.flush()

def is_interrupted():
    """Verifica si se ha solicitado una interrupción"""
    global interrupt_requested
    with interrupt_lock:
        return interrupt_requested

def setup_interrupt_handler():
    """Configura el manejador de interrupción"""
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

def safe_executor(executor_func, max_workers, *args, **kwargs):
    """
    Wrapper seguro para ThreadPoolExecutor que respeta las interrupciones
    """
    if is_interrupted():
        return []
    
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Verificar interrupción antes de comenzar
            if is_interrupted():
                return []
            
            # Ejecutar la función del executor
            return executor_func(executor, *args, **kwargs)
            
    except KeyboardInterrupt:
        # Si se recibe KeyboardInterrupt, verificar si es una interrupción solicitada
        if is_interrupted():
            sys.stdout.write(f"\n{Fore.YELLOW}[!] Deteniendo threads...{Fore.RESET}\n")
            sys.stdout.flush()
            return []
        else:
            # Interrupción no solicitada, propagar
            raise

def check_interruption():
    """Verifica interrupción y sale si es necesario"""
    if is_interrupted():
        return True
    return False

def reset_interrupt_flag():
    """Resetea la bandera de interrupción (útil para operaciones múltiples)"""
    global interrupt_requested
    with interrupt_lock:
        interrupt_requested = False

