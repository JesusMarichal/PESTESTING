# -*- coding: utf-8 -*-
"""Carga centralizada de la configuración (config/settings.json)."""

import json
import os

_SETTINGS = None


def get_settings():
    """Devuelve el diccionario de configuración (cargado una sola vez)."""
    global _SETTINGS
    if _SETTINGS is None:
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        path = os.path.join(base, "config", "settings.json")
        with open(path, "r", encoding="utf-8") as fh:
            _SETTINGS = json.load(fh)
    return _SETTINGS
