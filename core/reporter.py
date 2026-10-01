# -*- coding: utf-8 -*-
"""Generación de informes: consola (colores), JSON y HTML autocontenido."""

import html as html_lib
import json
import os
import re
from datetime import datetime

from core import colors
from core.colors import C, paint

SEVERITY_STYLES = {
    "CRITICAL": (C.BOLD, C.RED),
    "HIGH": (C.RED,),
    "MEDIUM": (C.YELLOW,),
    "LOW": (C.CYAN,),
    "INFO": (C.BLUE,),
    "OK": (C.GREEN,),
}

HTML_SEVERITY = {
    "CRITICAL": "#c0392b",
    "HIGH": "#e67e22",
    "MEDIUM": "#f1c40f",
    "LOW": "#3498db",
    "INFO": "#7f8c8d",
    "OK": "#27ae60",
}

RISK_STYLES = {
    "BAJO": (C.BOLD, C.GREEN),
    "MEDIO": (C.BOLD, C.YELLOW),
    "ALTO": (C.BOLD, C.MAGENTA),
    "CRITICO": (C.BOLD, C.RED),
}

RISK_HTML = {
    "BAJO": "#27ae60",
    "MEDIO": "#f1c40f",
    "ALTO": "#e67e22",
    "CRITICO": "#c0392b",
}

WIDTH = 70


def _header(title):
    line = "=" * WIDTH
    return f"{line}\n{paint(title, C.BOLD, C.CYAN)}\n{line}"


def _section(title):
    return paint("-" * WIDTH + f"\n {title}\n" + "-" * WIDTH, C.BOLD)


def _kv(key, value, width=24):
    if value is None:
        value = "-"
    elif isinstance(value, (list, dict)):
        value = str(value)
    return f"   {str(key).ljust(width)}: {value}"


def _wrap(text, width=62):
    words, lines, current = text.split(), [], ""
    for word in words:
        if len(current) + len(word) + 1 > width:
            lines.append(current)
            current = word
        else:
            current = f"{current} {word}".strip()
    if current:
        lines.append(current)
    return "\n        ".join(lines)


def _findings_lines(hallazgos):
    lines = []
    if not hallazgos:
        lines.append("   Sin hallazgos.")
    for finding in hallazgos:
        severity = finding["severity"]
        styles = SEVERITY_STYLES.get(severity, ())
        badge = paint(f"[{severity:<8}]", *styles)
        title = paint(finding["title"], *styles) if styles else finding["title"]
        lines.append(f"   {badge} {title}")
        detail = finding["detail"]
        if len(detail) > 100:
            lines.append(f"        {_wrap(detail, width=WIDTH - 8)}")
        else:
            lines.append(f"        {detail}")
    return lines


def _risk_lines(riesgo):
    styles = RISK_STYLES.get(riesgo["nivel"], ())
    level_txt = paint(f"{riesgo['nivel']}", *styles)
    score_txt = paint(f"{riesgo['puntuacion']}/100", *styles)
    resumen = riesgo["resumen"]
    parts = [f"{sev}: {resumen[sev]}" for sev in
             ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "OK") if resumen.get(sev)]
    lines = [
        f"   Nivel de riesgo : {level_txt}",
        f"   Puntuacion      : {score_txt}",
        "   Detalle         : " + (", ".join(parts) if parts else "sin hallazgos"),
    ]
    return lines


# ------------------------------------------------------------- consola URL

def print_report(report, color=True):
    colors.set_enabled(color)
    out = []
    out.append(_header(f" {report['tool']} v{report['version']} | {report['modulo']}"))
    out.append(_kv("Objetivo", report["objetivo"]))
    out.append(_kv("Fecha", report["fecha_analisis"].replace("T", " ").split(".")[0]))
    out.append(_kv("Modo", report["modo"]))

    est = report["estructura"]
    out.append(_section("ESTRUCTURA DE LA URL"))
    for key in ("url_normalizada", "esquema", "host", "puerto", "ruta", "query",
                "fragmento", "usuario", "parametros", "etiquetas_host",
                "profundidad_ruta", "longitud_url"):
        out.append(_kv(key.replace("_", " "), est.get(key)))

    red = report["red"]
    if red.get("enabled"):
        out.append(_section("RED / DNS"))
        out.append(_kv("resuelve", red.get("resuelve")))
        out.append(_kv("ipv4", red.get("ipv4")))
        out.append(_kv("ipv6", red.get("ipv6")))
        out.append(_kv("ptr", red.get("ptr")))
        out.append(_kv("red privada", red.get("red_privada", "-")))

    http = report["http"]
    if http.get("enabled"):
        out.append(_section("HTTP"))
        if http.get("error"):
            out.append(_kv("error", http["error"]))
        else:
            out.append(_kv("estado final", http.get("estado_final")))
            out.append(_kv("url final", http.get("url_final")))
            if http.get("redirecciones"):
                out.append(f"   cadena de redirecciones ({len(http['redirecciones'])} salto(s)):")
                for hop in http["redirecciones"]:
                    out.append(f"     [{hop['estado']}] {hop['desde']}")
                    out.append(f"       -> {hop['a']}")
            else:
                out.append("   cadena de redirecciones: sin redirecciones")

    tls = report["tls"]
    if tls.get("enabled"):
        out.append(_section("TLS / CERTIFICADO"))
        for key in ("protocolo", "cifrado", "emisor", "sujeto", "expira", "num_san"):
            out.append(_kv(key, tls.get(key)))

    hallazgos = report["hallazgos"]
    out.append(_section(f"HALLAZGOS ({len(hallazgos)})"))
    out.extend(_findings_lines(hallazgos))

    out.append(_section("EVALUACION DE RIESGO"))
    out.extend(_risk_lines(report["riesgo"]))
    out.append("=" * WIDTH)
    return "\n".join(out)


# ---------------------------------------------------------- consola escaneo

def print_scan_report(report, color=True):
    colors.set_enabled(color)
    out = []
    out.append(_header(f" {report['tool']} v{report['version']} | {report['modulo']}"))
    out.append(_kv("Objetivo", report["objetivo"]))
    out.append(_kv("Fecha", report["fecha_analisis"].replace("T", " ").split(".")[0]))
    out.append(_kv("Modo", report["modo"]))

    out.append(_section("RESUMEN"))
    for key, value in report.get("resumen", []):
        out.append(_kv(key, value))

    abiertos = report.get("puertos_abiertos", [])
    out.append(_section(f"PUERTOS ABIERTOS ({len(abiertos)})"))
    if not abiertos:
        out.append("   Ninguno en el rango escaneado.")
    else:
        out.append(f"   {'PUERTO':>6}  {'SERVICIO':<18} BANNER")
        for entry in abiertos:
            banner = entry.get("banner") or "-"
            out.append(f"   {entry['puerto']:>6}  {entry['servicio']:<18} {banner}")

    hallazgos = report["hallazgos"]
    out.append(_section(f"HALLAZGOS ({len(hallazgos)})"))
    out.extend(_findings_lines(hallazgos))

    out.append(_section("EVALUACION DE RIESGO"))
    out.extend(_risk_lines(report["riesgo"]))
    out.append("=" * WIDTH)
    return "\n".join(out)


# ------------------------------------------------------------------- JSON

def save_json(report, path):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)
    return path


# ------------------------------------------------------------------- HTML

def _esc(value):
    return html_lib.escape(str(value if value is not None else "-"))


def _html_kv_table(data, keys=None):
    items = keys if keys else data.keys()
    rows = []
    for key in items:
        value = data.get(key)
        if isinstance(value, (list, dict)):
            value = ", ".join(str(v) for v in value) if value else "-"
        rows.append(
            f"<tr><th>{_esc(key.replace('_', ' '))}</th><td>{_esc(value)}</td></tr>"
        )
    return "<table class='kv'>" + "".join(rows) + "</table>"


def _html_pairs_table(pairs):
    rows = "".join(f"<tr><th>{_esc(k)}</th><td>{_esc(v)}</td></tr>" for k, v in pairs)
    return f"<table class='kv'>{rows}</table>"


def _html_findings(hallazgos):
    if not hallazgos:
        return "<p class='ok'>Sin hallazgos.</p>"
    rows = []
    for f in hallazgos:
        color = HTML_SEVERITY.get(f["severity"], "#555")
        rows.append(
            f"<tr><td><span class='badge' style='background:{color}'>{_esc(f['severity'])}</span></td>"
            f"<td>{_esc(f['check'])}</td><td><strong>{_esc(f['title'])}</strong></td>"
            f"<td>{_esc(f['detail'])}</td></tr>"
        )
    return ("<table class='findings'><tr><th>Severidad</th><th>Categoria</th>"
            "<th>Titulo</th><th>Detalle</th></tr>" + "".join(rows) + "</table>")


_HTML_CSS = """
  body { font-family: 'Segoe UI', Arial, sans-serif; margin: 0; background: #0f1117; color: #e6e6e6; }
  .container { max-width: 1000px; margin: 0 auto; padding: 30px; }
  h1 { color: #00d4ff; border-bottom: 2px solid #00d4ff; padding-bottom: 10px; }
  h2 { color: #00d4ff; margin-top: 35px; }
  .meta { color: #9aa0a6; font-size: 0.9em; }
  .risk { display: inline-block; padding: 14px 26px; border-radius: 10px; font-size: 1.3em;
          font-weight: bold; color: #fff; background: __RISK__; }
  .score { font-size: 1.1em; margin-left: 16px; color: #cfcfcf; }
  table { border-collapse: collapse; width: 100%; margin-top: 12px; }
  th, td { border: 1px solid #2a2f3a; padding: 8px 10px; text-align: left; font-size: 0.92em; }
  table.kv th { width: 220px; background: #171b24; color: #00d4ff; }
  table.kv td { background: #12151d; word-break: break-all; }
  .findings th { background: #171b24; color: #00d4ff; }
  .badge { display: inline-block; padding: 3px 8px; border-radius: 4px; color: #fff;
           font-size: 0.78em; font-weight: bold; min-width: 70px; text-align: center; }
  .ok { color: #27ae60; }
  ul.redirects li { margin: 6px 0; font-size: 0.9em; }
  code { color: #ffb86c; }
  footer { margin-top: 45px; color: #555a64; font-size: 0.8em; border-top: 1px solid #2a2f3a; padding-top: 14px; }
"""


def _html_doc(report, body):
    riesgo = report["riesgo"]
    css = _HTML_CSS.replace("__RISK__", RISK_HTML.get(riesgo["nivel"], "#555"))
    return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>Informe {_esc(report['modulo'])} - {_esc(report['objetivo'])}</title>
<style>{css}</style>
</head>
<body>
<div class="container">
  <h1>PESTesting Suite v{_esc(report['version'])} &mdash; {_esc(report['modulo'])}</h1>
  <p class="meta">Objetivo: <strong>{_esc(report['objetivo'])}</strong><br>
     Fecha: {_esc(report['fecha_analisis'])} &nbsp;|&nbsp; Modo: {_esc(report['modo'])}</p>

  <div style="margin-top:25px">
    <span class="risk">RIESGO: {_esc(riesgo['nivel'])}</span>
    <span class="score">Puntuacion: {riesgo['puntuacion']}/100 &middot;
      {riesgo['total_hallazgos']} hallazgo(s)</span>
  </div>

  {body}

  <footer>Generado por PESTesting Suite &mdash; usar solo contra sistemas con autorizacion expresa.</footer>
</div>
</body>
</html>"""


def build_html(report):
    red = report["red"]
    http = report["http"]
    tls = report["tls"]

    redirects = ""
    if http.get("redirecciones"):
        rows = "".join(
            f"<li><code>{_esc(h['estado'])}</code> {_esc(h['desde'])} &rarr; {_esc(h['a'])}</li>"
            for h in http["redirecciones"]
        )
        redirects = f"<h2>Cadena de redirecciones</h2><ul class='redirects'>{rows}</ul>"

    body = f"""
  <h2>Estructura de la URL</h2>
  {_html_kv_table(report['estructura'], ['url_normalizada', 'esquema', 'host', 'puerto',
    'ruta', 'query', 'fragmento', 'usuario', 'parametros', 'etiquetas_host',
    'profundidad_ruta', 'longitud_url'])}

  {f"<h2>Red / DNS</h2>" + _html_kv_table(red, ['resuelve', 'ipv4', 'ipv6', 'ptr', 'red_privada']) if red.get('enabled') else ""}

  {f"<h2>HTTP</h2>" + _html_kv_table(http, ['estado_final', 'url_final', 'error']) if http.get('enabled') else ""}
  {redirects}

  {f"<h2>TLS / Certificado</h2>" + _html_kv_table(tls, ['protocolo', 'cifrado', 'emisor', 'sujeto', 'expira', 'num_san']) if tls.get('enabled') else ""}

  <h2>Hallazgos</h2>
  {_html_findings(report['hallazgos'])}"""
    return _html_doc(report, body)


def build_scan_html(report):
    abiertos = report.get("puertos_abiertos", [])
    if abiertos:
        rows = "".join(
            f"<tr><td>{_esc(e['puerto'])}</td><td>{_esc(e['servicio'])}</td>"
            f"<td>{_esc(e['banner'] or '-')}</td></tr>"
            for e in abiertos
        )
        ports_table = ("<table class='findings'><tr><th>Puerto</th><th>Servicio</th>"
                       f"<th>Banner</th></tr>{rows}</table>")
    else:
        ports_table = "<p class='ok'>Ningún puerto abierto en el rango escaneado.</p>"

    body = f"""
  <h2>Resumen</h2>
  {_html_pairs_table(report.get('resumen', []))}

  <h2>Puertos abiertos ({len(abiertos)})</h2>
  {ports_table}

  <h2>Hallazgos</h2>
  {_html_findings(report['hallazgos'])}"""
    return _html_doc(report, body)


def save_html(report, path):
    if report.get("modulo_slug") == "portscan":
        content = build_scan_html(report)
    else:
        content = build_html(report)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return path


# ------------------------------------------------------------------ salida

def save_report(report, output_dir, formats=("json", "html")):
    os.makedirs(output_dir, exist_ok=True)
    host = (report.get("estructura") or {}).get("host")
    if not host:
        host = next((v for k, v in report.get("resumen", []) if k == "IP"), None)
    if not host:
        host = report.get("objetivo")
    safe_host = re.sub(r"[^A-Za-z0-9.\-]+", "_", str(host))[:60] or "sin-host"
    prefix = report.get("modulo_slug", "url")
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    paths = []
    if "json" in formats:
        paths.append(save_json(report, os.path.join(output_dir, f"{prefix}_{safe_host}_{stamp}.json")))
    if "html" in formats:
        paths.append(save_html(report, os.path.join(output_dir, f"{prefix}_{safe_host}_{stamp}.html")))
    return paths
