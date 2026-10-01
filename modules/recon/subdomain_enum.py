# -*- coding: utf-8 -*-
"""
Enumerador de subdominios (módulo de reconocimiento).

Técnicas:
- Fuerza bruta DNS con wordlist integrada (sin dependencias externas)
- Resolución concurrente con ThreadPoolExecutor
- Detección de wildcard DNS (evita falsos positivos)
- Detección de registros A, AAAA y CNAME
- Hallazgos de riesgo: subdominios sensibles expuestos (admin, vpn, dev…)
- Informe compatible con el reporter unificado
"""

import hashlib
import random
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict
from datetime import datetime, timezone

from core import VERSION
from core.config import get_settings
from core.findings import Finding, SEVERITY_ORDER, compute_risk

# ------------------------------------------------------------------ wordlist

# ~350 prefijos ordenados por probabilidad de existir
WORDLIST = [
    # muy comunes
    "www", "mail", "ftp", "webmail", "smtp", "pop", "imap", "ns1", "ns2",
    "ns3", "mx", "mx1", "mx2", "dns", "dns1", "dns2",
    # administración y paneles
    "admin", "administrador", "panel", "cpanel", "whm", "plesk", "directadmin",
    "portal", "manager", "management", "console", "control", "dashboard",
    # entornos
    "dev", "develop", "development", "devel", "staging", "stage", "stg",
    "test", "testing", "qa", "uat", "pre", "preprod", "sandbox", "demo",
    "beta", "alpha", "preview", "lab", "labs",
    # producción y CDN
    "cdn", "cdn1", "cdn2", "media", "static", "assets", "img", "images",
    "files", "download", "downloads", "upload", "uploads",
    # API y servicios
    "api", "api2", "apiv1", "apiv2", "rest", "graphql", "ws", "websocket",
    "socket", "rpc", "backend", "service", "services", "gateway", "proxy",
    "load", "lb", "balancer",
    # seguridad y acceso remoto
    "vpn", "vpn1", "vpn2", "ssh", "rdp", "remote", "access", "secure",
    "ssl", "auth", "login", "sso", "idp", "oauth",
    # git y CI/CD
    "git", "gitlab", "github", "bitbucket", "svn", "jenkins", "ci", "cd",
    "build", "deploy", "registry", "nexus", "artifactory", "jira", "confluence",
    # bases de datos y herramientas
    "db", "database", "sql", "mysql", "postgres", "mongodb", "redis", "elastic",
    "kibana", "grafana", "prometheus", "influxdb", "zabbix", "nagios",
    "monitoring", "monitor",
    # correo y comunicaciones
    "smtp", "pop3", "imap", "autodiscover", "autoconfig", "exchange",
    "owa", "outlook", "calendar", "meet", "video", "chat", "slack",
    # intranet y corporativo
    "intranet", "internal", "corp", "corporate", "office", "extranet",
    "partner", "partners", "b2b", "crm", "erp", "hr", "helpdesk",
    "support", "ticket", "tickets",
    # e-commerce y pagos
    "shop", "store", "cart", "checkout", "pay", "payment", "billing",
    "invoice", "account", "accounts", "myaccount", "customer",
    # blog y contenido
    "blog", "news", "wiki", "docs", "documentation", "help", "forum",
    "community", "status", "statuspage",
    # backup y almacenamiento
    "backup", "backups", "archive", "storage", "s3", "vault", "nas",
    # regionales y numerados
    "us", "eu", "uk", "de", "fr", "es", "latam", "asia",
    "1", "2", "3", "m", "mobile", "app", "old", "new", "legacy",
    # otros habituales en pentest
    "phpmyadmin", "adminer", "webdav", "exchange", "cas", "sts",
    "token", "smtp-out", "mail2", "mx3", "relay", "outbound",
]

# Subdominios que si existen deberían generar alertas
SENSITIVE_SUBDOMAINS = {
    "admin", "administrador", "panel", "cpanel", "whm", "plesk", "directadmin",
    "manager", "management", "console", "control", "dashboard", "phpmyadmin",
    "adminer", "webdav", "dev", "develop", "development", "staging", "stage",
    "stg", "test", "testing", "qa", "uat", "pre", "preprod", "sandbox", "beta",
    "alpha", "lab", "labs", "vpn", "vpn1", "vpn2", "ssh", "rdp", "remote",
    "access", "git", "gitlab", "github", "bitbucket", "svn", "jenkins", "ci",
    "cd", "build", "deploy", "registry", "nexus", "artifactory", "jira",
    "confluence", "db", "database", "sql", "mysql", "postgres", "mongodb",
    "redis", "elastic", "kibana", "grafana", "prometheus", "influxdb", "zabbix",
    "nagios", "backup", "backups", "archive", "old", "legacy", "intranet",
    "internal", "corp", "extranet", "monitor", "monitoring",
}


# ------------------------------------------------------------------ utilidades

def _random_subdomain(length=12):
    """Genera un subdominio aleatorio para detectar wildcards."""
    chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    seed = hashlib.md5(str(time.time()).encode()).hexdigest()
    rng = random.Random(seed)
    return "".join(rng.choice(chars) for _ in range(length))


def _resolve(fqdn: str, timeout: float) -> tuple[list[str], str | None]:
    """
    Intenta resolver un FQDN.
    Devuelve (lista_IPs, cname_o_None).
    Lanza socket.gaierror si no resuelve.
    """
    orig_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        # Primero intentamos resolver el host
        infos = socket.getaddrinfo(fqdn, None)
        ips = sorted({i[4][0] for i in infos})
        return ips, None
    finally:
        socket.setdefaulttimeout(orig_timeout)


# ------------------------------------------------------------------ escáner

class SubdomainEnumerator:
    """Motor de enumeración de subdominios por fuerza bruta DNS."""

    def __init__(self, domain: str, wordlist: list[str] | None = None,
                 threads: int = 50, timeout: float = 3.0):
        self.settings = get_settings()
        self.domain = self._clean_domain(domain)
        self.wordlist = wordlist if wordlist else WORDLIST
        self.threads = max(1, min(threads, 200))
        self.timeout = max(0.5, float(timeout))
        self.findings: list[Finding] = []
        self._wildcard_ips: set[str] = set()

    # ---------------------------------------------------------------- utils

    def _add(self, check: str, title: str, severity: str, detail: str):
        self.findings.append(Finding(check, title, severity, detail))

    @staticmethod
    def _clean_domain(domain: str) -> str:
        """Elimina esquema y trailing slash del dominio objetivo."""
        d = domain.strip().lower()
        for prefix in ("https://", "http://"):
            if d.startswith(prefix):
                d = d[len(prefix):]
        return d.split("/")[0]

    # ---------------------------------------------------------------- wildcard

    def _detect_wildcard(self) -> bool:
        """
        Resuelve un subdominio aleatorio para detectar si el dominio
        tiene un wildcard DNS (*.dominio.com → siempre resuelve).
        """
        fake = f"{_random_subdomain()}.{self.domain}"
        try:
            ips, _ = _resolve(fake, self.timeout)
            self._wildcard_ips = set(ips)
            return True
        except (socket.gaierror, OSError):
            return False

    # ---------------------------------------------------------------- worker

    def _check_subdomain(self, prefix: str) -> dict | None:
        """Intenta resolver prefix.domain. Devuelve dict si existe, None si no."""
        fqdn = f"{prefix}.{self.domain}"
        try:
            ips, cname = _resolve(fqdn, self.timeout)
            # ignorar si las IPs coinciden con el wildcard
            if self._wildcard_ips and set(ips) == self._wildcard_ips:
                return None
            return {"subdominio": fqdn, "prefix": prefix, "ips": ips, "cname": cname}
        except (socket.gaierror, OSError):
            return None

    # ---------------------------------------------------------------- scan

    def enumerate(self) -> dict:
        """Ejecuta la enumeración y devuelve el informe."""
        self.findings = []
        started = datetime.now(timezone.utc)
        t0 = time.monotonic()

        # --- verificar que el dominio base resuelve ---
        try:
            base_ips, _ = _resolve(self.domain, self.timeout)
            self._add("base", f"Dominio base '{self.domain}' resuelve", "OK",
                      f"IPs: {', '.join(base_ips[:5])}")
        except (socket.gaierror, OSError) as exc:
            self._add("base", f"Dominio base '{self.domain}' no resuelve", "HIGH",
                      f"No se pudo resolver el dominio objetivo: {exc}")
            return self._build_report(started, [], False, 0)

        # --- detección de wildcard ---
        has_wildcard = self._detect_wildcard()
        if has_wildcard:
            self._add("wildcard", "Wildcard DNS detectado", "MEDIUM",
                      f"El dominio '{self.domain}' tiene un wildcard DNS activo. "
                      "Se filtrarán los subdominios que resuelvan a las mismas IPs "
                      f"({', '.join(self._wildcard_ips)}). Puede haber falsos negativos.")

        # --- enumeración concurrente ---
        found: list[dict] = []
        total = len(self.wordlist)
        done = 0
        show_progress = False  # sin TTY no imprimimos progreso

        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            futures = {pool.submit(self._check_subdomain, prefix): prefix
                       for prefix in self.wordlist}
            for future in as_completed(futures):
                result = future.result()
                done += 1
                if result:
                    found.append(result)

        found.sort(key=lambda e: e["subdominio"])
        duration = time.monotonic() - t0

        # --- análisis de hallazgos ---
        self._analyze(found)

        self.findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
        risk = compute_risk(self.findings, self.settings["risk_thresholds"])

        return self._build_report(started, found, has_wildcard, total, duration, risk)

    # ---------------------------------------------------------------- análisis

    def _analyze(self, found: list[dict]):
        if not found:
            self._add("subdominios", "Sin subdominios encontrados", "INFO",
                      "No se descubrió ningún subdominio en la wordlist utilizada.")
            return

        self._add("subdominios", f"{len(found)} subdominio(s) descubierto(s)", "INFO",
                  ", ".join(e["subdominio"] for e in found[:20])
                  + (" …" if len(found) > 20 else ""))

        for entry in found:
            prefix = entry["prefix"]
            sub = entry["subdominio"]
            ips = entry["ips"]

            # subdominio sensible expuesto
            if prefix in SENSITIVE_SUBDOMAINS:
                self._add("exposicion",
                          f"Subdominio sensible expuesto: {sub}",
                          "HIGH",
                          f"'{sub}' → {', '.join(ips[:3])}. "
                          "Este tipo de subdominio suele exponer paneles de administración, "
                          "entornos de desarrollo o servicios internos.")

    # ---------------------------------------------------------------- informe

    def _build_report(self, started, found, has_wildcard, total_checked,
                      duration=0.0, risk=None):
        if risk is None:
            risk = compute_risk(self.findings, self.settings["risk_thresholds"])
        return {
            "tool": "PESTesting Suite",
            "modulo": "Enumeración de Subdominios",
            "modulo_slug": "subdomain",
            "version": VERSION,
            "objetivo": self.domain,
            "fecha_analisis": started.isoformat(),
            "modo": (f"DNS brute-force | {total_checked} prefijos | "
                     f"{self.threads} hilos | timeout {self.timeout}s"),
            "resumen": [
                ["Dominio objetivo", self.domain],
                ["Wildcard DNS", "Sí (filtrado activo)" if has_wildcard else "No"],
                ["Prefijos probados", total_checked],
                ["Subdominios encontrados", len(found)],
                ["Duración", f"{duration:.2f} s"],
            ],
            "subdominios": found,
            "hallazgos": [asdict(f) for f in self.findings],
            "riesgo": risk,
        }
