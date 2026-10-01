# -*- coding: utf-8 -*-
"""
Escáner de puertos TCP (connect scan) multihilo.

Características:
- Escaneo TCP por conexión completa con ThreadPoolExecutor
- Presets ('common', 'all'), rangos y listas explícitas de puertos
- Clasificación por puerto: abierto / cerrado / filtrado
- Identificación de servicio por puerto y captura de banners
  (HTTP/HTTPS, saludos de protocolo, sondas Redis/Memcached)
- Hallazgos de riesgo para servicios peligrosos expuestos
"""

import ipaddress
import re
import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict
from datetime import datetime, timezone

from core import VERSION
from core.config import get_settings
from core.findings import Finding, SEVERITY_ORDER, compute_risk

HTTP_PORTS = {
    80, 88, 591, 2082, 2083, 2086, 2087, 2095, 2096, 2375, 2376, 3000,
    3128, 5000, 5001, 5601, 5985, 5986, 7001, 7777, 8000, 8008, 8080, 8081,
    8088, 8089, 8118, 8123, 8222, 8333, 8443, 8500, 8888, 9000, 9001, 9080,
    9090, 9091, 9200, 9443, 9998, 9999, 10000,
}
TLS_HTTP_PORTS = {443, 2083, 2087, 2096, 2376, 8443, 9091, 9443}
GREETING_PORTS = {21, 22, 25, 110, 143, 587, 3306, 6667}
PROBE_PAYLOADS = {6379: b"PING\r\n", 11211: b"version\r\n"}

IP_PATTERN = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def parse_ports(spec, cfg):
    """Convierte una especificación de puertos ('common', 'all', '22,80', '1-1024')."""
    spec = (spec or "common").strip().lower()
    if spec in ("all", "completo"):
        return list(range(1, 65536))
    if spec in ("common", "comunes", "top", "top100"):
        return list(cfg["common_ports"])

    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            low, _, high = part.partition("-")
            if not (low.isdigit() and high.isdigit()):
                raise ValueError(f"rango de puertos inválido: '{part}'")
            lo, hi = int(low), int(high)
            if lo > hi:
                lo, hi = hi, lo
            ports.update(range(max(1, lo), min(65535, hi) + 1))
        elif part.isdigit():
            port = int(part)
            if not 1 <= port <= 65535:
                raise ValueError(f"puerto fuera de rango (1-65535): {part}")
            ports.add(port)
        else:
            raise ValueError(f"puerto inválido: '{part}'")
    if not ports:
        raise ValueError("no se especificó ningún puerto válido")
    return sorted(ports)


class PortScanner:
    """Motor de escaneo TCP multihilo."""

    def __init__(self, target, ports_spec="common", threads=None, timeout=None,
                 banner=True, show_progress=None):
        self.settings = get_settings()
        cfg = self.settings["port_scan"]
        self.target = target.strip()
        self.threads = max(1, min(threads or cfg["default_threads"], cfg["max_threads"]))
        self.timeout = cfg["default_timeout"] if timeout is None else max(0.2, float(timeout))
        self.banner_enabled = banner
        self.banner_timeout = max(self.timeout, 2.0)
        self.show_progress = sys.stdout.isatty() if show_progress is None else bool(show_progress)
        self.findings = []
        self.ports = parse_ports(ports_spec, cfg)
        self.ip = None
        self.hostname = None
        self.ptr = None

    def _add(self, check, title, severity, detail):
        self.findings.append(Finding(check, title, severity, detail))

    # -------------------------------------------------------------- escaneo

    def scan(self):
        started = datetime.now(timezone.utc)
        t0 = time.monotonic()
        cfg = self.settings["port_scan"]
        stats = {"abierto": 0, "cerrado": 0, "filtrado": 0}
        open_ports = []

        error = self._resolve()
        if not error:
            states = self._run_scan()
            stats = states["stats"]
            open_ports = states["abiertos"]

        duration = time.monotonic() - t0
        results = self._collect_details(open_ports) if open_ports else []
        self._evaluate(error, stats, results)

        self.findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
        risk = compute_risk(self.findings, self.settings["risk_thresholds"])

        resumen = [
            ["Objetivo", self.target],
            ["IP", self.ip or "-"],
        ]
        if self.ptr:
            resumen.append(["Host inverso (PTR)", self.ptr])
        if error:
            resumen.append(["Error", error])
        resumen.extend([
            ["Puertos escaneados", len(self.ports)],
            ["Abiertos", stats["abierto"]],
            ["Cerrados", stats["cerrado"]],
            ["Filtrados", stats["filtrado"]],
            ["Duración", f"{duration:.2f} s"],
        ])

        return {
            "tool": "PESTesting Suite",
            "modulo": "Escaneo de Puertos",
            "modulo_slug": "portscan",
            "version": VERSION,
            "objetivo": self.target,
            "fecha_analisis": started.isoformat(),
            "modo": (f"TCP connect scan | {len(self.ports)} puerto(s) | "
                     f"{self.threads} hilo(s) | timeout {self.timeout}s"),
            "resumen": resumen,
            "puertos_abiertos": results,
            "hallazgos": [asdict(f) for f in self.findings],
            "riesgo": risk,
        }

    def _resolve(self):
        """Resuelve el objetivo a IP. Devuelve None si OK o un mensaje de error."""
        if IP_PATTERN.match(self.target):
            self.ip = self.target
        else:
            try:
                infos = socket.getaddrinfo(self.target, None, socket.AF_INET)
                self.ip = infos[0][4][0]
                self.hostname = self.target
            except socket.gaierror as exc:
                self._add("dns", "Resolución DNS fallida", "HIGH",
                          f"No se pudo resolver '{self.target}': {exc}")
                return str(exc)
        try:
            self.ptr = socket.gethostbyaddr(self.ip)[0]
        except (socket.herror, OSError):
            self.ptr = None
        try:
            addr = ipaddress.ip_address(self.ip)
            if addr.is_private or addr.is_loopback:
                self._add("objetivo", "Objetivo en red privada", "INFO",
                          f"{self.ip} es una dirección privada o de loopback; "
                          "escaneo de infraestructura interna.")
        except ValueError:
            pass
        return None

    def _run_scan(self):
        total = len(self.ports)
        stats = {"abierto": 0, "cerrado": 0, "filtrado": 0}
        abiertos = []
        done = 0
        workers = max(1, min(self.threads, total))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(self._tcp_check, port) for port in self.ports]
            for future in as_completed(futures):
                port, state = future.result()
                done += 1
                stats[state] += 1
                if state == "abierto":
                    abiertos.append(port)
                if self.show_progress and (done % 25 == 0 or done == total):
                    pct = done * 100.0 / total
                    print(f"\r   Progreso: {done}/{total} ({pct:.0f}%)", end="", flush=True)
        if self.show_progress:
            print()
        abiertos.sort()
        stats["abierto"] = len(abiertos)
        return {"stats": stats, "abiertos": abiertos}

    def _tcp_check(self, port):
        try:
            sock = socket.create_connection((self.ip, port), timeout=self.timeout)
            sock.close()
            return port, "abierto"
        except ConnectionRefusedError:
            return port, "cerrado"
        except socket.timeout:
            return port, "filtrado"
        except OSError:
            return port, "filtrado"

    # ------------------------------------------------------------- detalles

    def _collect_details(self, open_ports):
        services = self.settings["port_scan"]["service_names"]
        results = []
        for port in open_ports:
            service = services.get(str(port)) or self._getserv(port)
            banner = self._grab_banner(port) if self.banner_enabled else None
            results.append({"puerto": port, "servicio": service, "banner": banner})
        return results

    @staticmethod
    def _getserv(port):
        try:
            return socket.getservbyport(port, "tcp")
        except OSError:
            return "desconocido"

    def _grab_banner(self, port):
        try:
            sock = socket.create_connection((self.ip, port), timeout=self.timeout)
        except OSError:
            return None
        try:
            sock.settimeout(self.banner_timeout)
            if port in TLS_HTTP_PORTS:
                context = ssl._create_unverified_context()
                sock = context.wrap_socket(sock)
                return self._http_banner(sock)
            if port in HTTP_PORTS:
                return self._http_banner(sock)

            if port in GREETING_PORTS:
                data = sock.recv(512)
            elif port in PROBE_PAYLOADS:
                sock.sendall(PROBE_PAYLOADS[port])
                data = sock.recv(512)
            else:
                data = self._recv_or(sock)
                if not data:
                    try:
                        sock.sendall(b"\r\n")
                        data = self._recv_or(sock)
                    except (socket.timeout, OSError):
                        pass
            return self._clean_banner(data)
        except (socket.timeout, OSError):
            return None
        finally:
            try:
                sock.close()
            except OSError:
                pass

    @staticmethod
    def _recv_or(sock):
        try:
            return sock.recv(128)
        except (socket.timeout, OSError):
            return b""

    def _http_banner(self, sock):
        try:
            host = self.hostname or self.ip
            payload = (f"HEAD / HTTP/1.0\r\nHost: {host}\r\n"
                       f"User-Agent: {self.settings['request_headers']['User-Agent']}\r\n"
                       "Accept: */*\r\n\r\n").encode("latin-1", "ignore")
            sock.sendall(payload)
            data = self._recv_or(sock)
        except (socket.timeout, OSError):
            return None
        if not data:
            return None
        text = data.decode("latin-1", "ignore")
        lines = text.split("\r\n")
        first = lines[0].strip() if lines else ""
        server = ""
        for line in lines[1:]:
            if line.lower().startswith("server:"):
                server = line.split(":", 1)[1].strip()
                break
        parts = [p for p in (first, f"Server: {server}" if server else "") if p]
        return self._clean_banner(" | ".join(parts).encode("latin-1", "ignore"))

    @staticmethod
    def _clean_banner(data):
        if not data:
            return None
        text = data.decode("latin-1", "ignore")
        text = "".join(ch if ch.isprintable() else " " for ch in text)
        text = re.sub(r"\s+", " ", text).strip()
        return text[:120] or None

    # ------------------------------------------------------------ hallazgos

    def _evaluate(self, error, stats, results):
        if error:
            return
        if not self.ports:
            self._add("escaneo", "Sin puertos válidos", "MEDIUM",
                      "La especificación de puertos no contiene ningún puerto.")
            return

        risky = self.settings["port_scan"]["risky_services"]
        for entry in results:
            rule = risky.get(str(entry["puerto"]))
            if rule:
                severity, reason = rule
                extra = f" | Banner: {entry['banner']}" if entry["banner"] else ""
                self._add("servicio",
                          f"Puerto {entry['puerto']} ({entry['servicio']}) expuesto",
                          severity, reason + extra)

        threshold = self.settings["port_scan"]["open_ports_finding_threshold"]
        if stats["abierto"] > threshold:
            self._add("escaneo", "Superficie de ataque amplia", "LOW",
                      f"Hay {stats['abierto']} puertos abiertos; revisa si todos los "
                      "servicios son necesarios (minimizar superficie expuesta).")

        if stats["abierto"] == 0:
            if stats["filtrado"] == len(self.ports):
                self._add("escaneo", "Host sin respuesta en ningún puerto", "MEDIUM",
                          "Todos los puertos aparecen filtrados: el host está caído, "
                          "protegido por un firewall drop-all o el objetivo es incorrecto.")
            else:
                self._add("escaneo", "Sin puertos abiertos", "OK",
                          f"Ninguno de los {len(self.ports)} puertos escaneados está abierto "
                          "(host activo, servicios cerrados).")
