#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PESTesting Suite - Herramienta integral de ciberseguridad.

Uso:
    python main.py url <objetivo> [opciones]
    python main.py --version
"""

import argparse
import os
import sys

from core import colors, reporter
from modules.recon.url_analyzer import URLAnalyzer
from modules.recon.port_scanner import PortScanner, parse_ports

VERSION = "0.1.1"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BANNER = r"""
  ____  _____ ____ _____ ___ ____      _    __  __
 |  _ \| ___|  _ \_   _|_ _/ ___|    / \  |  \/  |
 | |_) |  _| | | | || |  | |\___ \   / _ \ | |\/| |
 |  __/| |___| |_| || |  | | ___) | / ___ \| |  | |
 |_|   |_____|____/ |_| |___|____(_)_/   \_\_|  |_|
        Suite de Ciberseguridad - v{version}
"""


def build_parser():
    parser = argparse.ArgumentParser(
        prog="pestesting",
        description="Suite de ciberseguridad: analisis, ataque y defensa.",
    )
    parser.add_argument("--version", action="version", version=f"PESTesting Suite {VERSION}")
    parser.add_argument("--no-banner", action="store_true", help="oculta el banner inicial")

    sub = parser.add_subparsers(dest="command", metavar="comando")

    # --- subcomando: url ---
    p_url = sub.add_parser("url", help="analiza una URL (reconocimiento)")
    p_url.add_argument("target", help="URL a analizar (p. ej. https://ejemplo.com)")
    p_url.add_argument("--timeout", type=float, default=8.0,
                       help="segundos de espera para comprobaciones de red (defecto: 8)")
    p_url.add_argument("--offline", action="store_true",
                      help="omite comprobaciones de red (DNS/HTTP/TLS)")
    p_url.add_argument("--no-color", action="store_true", help="desactiva los colores")
    p_url.add_argument("--no-save", action="store_true",
                      help="no guarda informes en disco")
    p_url.add_argument("--format", choices=["json", "html", "both"], default="both",
                       help="formato de informe a guardar (defecto: both)")
    p_url.add_argument("--output-dir", default=os.path.join(BASE_DIR, "reports"),
                       help="directorio de salida de los informes")

    # --- subcomando: scan ---
    p_scan = sub.add_parser("scan", help="escanea puertos TCP de un host")
    p_scan.add_argument("target", help="IP o nombre de host a escanear (ej. 192.168.1.1 o ejemplo.com)")
    p_scan.add_argument("--ports", default="common",
                        help=("puertos a escanear: 'common' (defecto), 'all', "
                              "lista '22,80,443' o rango '1-1024'"))
    p_scan.add_argument("--threads", type=int, default=100,
                        help="número de hilos concurrentes (defecto: 100, máx: 500)")
    p_scan.add_argument("--timeout", type=float, default=1.5,
                        help="timeout TCP por puerto en segundos (defecto: 1.5)")
    p_scan.add_argument("--no-banner", action="store_true",
                        help="desactiva el banner grabbing")
    p_scan.add_argument("--no-color", action="store_true", help="desactiva los colores")
    p_scan.add_argument("--no-save", action="store_true",
                        help="no guarda informes en disco")
    p_scan.add_argument("--format", choices=["json", "html", "both"], default="both",
                        help="formato de informe a guardar (defecto: both)")
    p_scan.add_argument("--output-dir", default=os.path.join(BASE_DIR, "reports"),
                        help="directorio de salida de los informes")
    return parser


def cmd_url(args):
    analyzer = URLAnalyzer(timeout=args.timeout, offline=args.offline)
    report = analyzer.analyze(args.target)

    print(reporter.print_report(report, color=not args.no_color))

    if not args.no_save:
        formats = ("json", "html") if args.format == "both" else (args.format,)
        paths = reporter.save_report(report, args.output_dir, formats=formats)
        colors.set_enabled(not args.no_color)
        for path in paths:
            print(colors.paint(f"   [informe] {path}", colors.C.GREEN))
    return 0


def cmd_scan(args):
    colors.set_enabled(not args.no_color)
    # validar especificación de puertos antes de lanzar el escáner
    from core.config import get_settings
    try:
        port_list = parse_ports(args.ports, get_settings()["port_scan"])
    except ValueError as exc:
        print(colors.paint(f"[ERROR] {exc}", colors.C.RED))
        return 1

    scanner = PortScanner(
        target=args.target,
        ports_spec=args.ports,
        threads=args.threads,
        timeout=args.timeout,
        banner=not args.no_banner,
    )
    report = scanner.scan()

    print(reporter.print_scan_report(report, color=not args.no_color))

    if not args.no_save:
        formats = ("json", "html") if args.format == "both" else (args.format,)
        paths = reporter.save_report(report, args.output_dir, formats=formats)
        for path in paths:
            print(colors.paint(f"   [informe] {path}", colors.C.GREEN))
    return 0


def main(argv=None):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

    parser = build_parser()
    args = parser.parse_args(argv)

    colors.set_enabled(sys.stdout.isatty() and os.environ.get("TERM") != "dumb")
    if not args.no_banner and args.command:
        colors.paint("")  # asegura inicializacion ANSI en Windows
        print(colors.paint(BANNER.format(version=VERSION), colors.C.CYAN))

    if args.command == "url":
        return cmd_url(args)

    if args.command == "scan":
        return cmd_scan(args)

    parser.print_help()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrumpido por el usuario.")
        sys.exit(130)
