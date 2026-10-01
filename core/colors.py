# -*- coding: utf-8 -*-
"""Manejo de colores ANSI para la salida por consola (con soporte Windows)."""

import os
import sys

_ENABLED = sys.stdout.isatty()


def _enable_windows_ansi():
    """Activa el procesamiento de secuencias ANSI en la consola de Windows."""
    if os.name == "nt":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
            mode = ctypes.c_uint32()
            if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                kernel32.SetConsoleMode(handle, mode.value | 0x0004)
        except Exception:
            pass


class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"


def set_enabled(value):
    global _ENABLED
    _ENABLED = bool(value)
    if _ENABLED:
        _enable_windows_ansi()


def is_enabled():
    return _ENABLED


def paint(text, *codes):
    """Aplica códigos de color ANSI si los colores están activados."""
    if not _ENABLED or not codes:
        return text
    return "".join(codes) + text + C.RESET
