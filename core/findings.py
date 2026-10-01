# -*- coding: utf-8 -*-
"""Modelo común de hallazgos y cálculo de riesgo para todos los módulos."""

from dataclasses import dataclass

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "OK"]
SEVERITY_ORDER = {name: idx for idx, name in enumerate(SEVERITIES)}
RISK_POINTS = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 4, "INFO": 1, "OK": 0}


@dataclass
class Finding:
    check: str
    title: str
    severity: str
    detail: str


def compute_risk(findings, thresholds):
    """Calcula la puntuación (0-100) y el nivel de riesgo de una lista de hallazgos."""
    total = sum(RISK_POINTS.get(f.severity, 0) for f in findings)
    score = min(total, 100)
    if score < thresholds["bajo"]:
        level = "BAJO"
    elif score < thresholds["medio"]:
        level = "MEDIO"
    elif score < thresholds["alto"]:
        level = "ALTO"
    else:
        level = "CRITICO"

    summary = {s: sum(1 for f in findings if f.severity == s) for s in SEVERITIES}
    return {
        "puntuacion": score,
        "nivel": level,
        "resumen": summary,
        "total_hallazgos": len(findings),
    }
