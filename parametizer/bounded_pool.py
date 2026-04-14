"""
Ejecución por lotes sobre ThreadPoolExecutor.

Evita crear un Future por cada URL de golpe: con listas enormes (modo -param)
eso dispara el uso de RAM y el kernel mata el proceso (OOM / zsh: killed).
"""
from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Iterable, List, Optional, Tuple, TypeVar

T = TypeVar("T")


def _default_chunk_size(max_workers: int) -> int:
    env = os.environ.get("NELUXMATIZER_POOL_CHUNK")
    if env and env.isdigit():
        return max(int(env), max_workers * 2)
    return max(min(max_workers * 64, 8192), max_workers * 2, 128)


def run_threadpool_in_chunks(
    fn: Callable[..., Any],
    items: Iterable[T],
    max_workers: int,
    chunk_size: Optional[int] = None,
    *,
    pass_tuple: bool = False,
) -> None:
    """
    Ejecuta fn sobre cada elemento sin acumular millones de futures.

    - pass_tuple=False: fn(item) — un solo argumento.
    - pass_tuple=True: fn(*item) — item es una tupla de argumentos.
    """
    if chunk_size is None:
        chunk_size = _default_chunk_size(max_workers)

    if isinstance(items, list):
        work: List[Any] = items
    else:
        work = list(items)

    if not work:
        return

    for start in range(0, len(work), chunk_size):
        chunk = work[start : start + chunk_size]
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            if pass_tuple:
                futures = [executor.submit(fn, *t) for t in chunk]
            else:
                futures = [executor.submit(fn, item) for item in chunk]
            for fut in as_completed(futures):
                try:
                    fut.result()
                except Exception:
                    pass


def run_threadpool_tasks_in_chunks(
    tasks: List[Tuple[Any, ...]],
    max_workers: int,
    chunk_size: Optional[int] = None,
) -> None:
    """
    tasks: lista de (callable, arg1, arg2, ...) — sin crear todos los futures de golpe.
    """
    if not tasks:
        return
    if chunk_size is None:
        chunk_size = _default_chunk_size(max_workers)
    for start in range(0, len(tasks), chunk_size):
        chunk = tasks[start : start + chunk_size]
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(t[0], *t[1:]) for t in chunk]
            for fut in as_completed(futures):
                try:
                    fut.result()
                except Exception:
                    pass


def run_threadpool_pending_bounded(
    task_iter,
    max_workers: int,
    pending_max: Optional[int] = None,
) -> None:
    """
    Consume un iterador de tuplas (fn, *args) sin materializar la lista completa.
    Mantiene como mucho pending_max futures en vuelo (patrón scan_sqli).
    """
    if pending_max is None:
        pending_max = max(max_workers * 200, 2000)
    pending: List[Any] = []

    def drain() -> None:
        for fut in as_completed(pending):
            try:
                fut.result()
            except Exception:
                pass
        pending.clear()

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        for task_tuple in task_iter:
            fn, *args = task_tuple
            pending.append(executor.submit(fn, *args))
            if len(pending) >= pending_max:
                drain()
        if pending:
            drain()
