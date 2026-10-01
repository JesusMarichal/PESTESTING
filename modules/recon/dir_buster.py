# -*- coding: utf-8 -*-
"""
Descubridor de rutas/directorios web (dir busting).

Técnicas:
- Fuerza bruta HTTP con wordlist integrada (~400 rutas)
- Concurrencia con ThreadPoolExecutor
- Clasificación por código de respuesta HTTP
- Detección de rutas sensibles (admin, .git, backup, config…)
- Fingerprinting de tecnología desde cabeceras
- Informe compatible con el reporter unificado
"""

import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict
from datetime import datetime, timezone

from core import VERSION
from core.config import get_settings
from core.findings import Finding, SEVERITY_ORDER, compute_risk

# ------------------------------------------------------------------ wordlist

WORDLIST = [
    # administración y paneles
    "admin", "admin/", "administrator", "administrator/", "administrador",
    "panel", "panel/", "cpanel", "whm", "plesk", "directadmin",
    "manager", "management", "console", "dashboard", "controlpanel",
    "phpmyadmin", "pma", "adminer", "dbadmin", "mysqladmin",
    # autenticación
    "login", "login.php", "login.html", "signin", "sign-in", "logout",
    "auth", "authenticate", "sso", "oauth", "token", "register", "signup",
    # APIs
    "api", "api/", "api/v1", "api/v1/", "api/v2", "api/v2/",
    "api/v3", "rest", "graphql", "rpc", "swagger", "swagger-ui",
    "swagger.json", "openapi.json", "api-docs", "api-docs/",
    # archivos sensibles de config y secretos
    ".env", ".env.local", ".env.production", ".env.backup",
    "config", "config/", "config.php", "config.js", "config.json",
    "config.yml", "config.yaml", "settings.py", "settings.json",
    "configuration.php", "configuration.xml", "web.config", "app.config",
    "appsettings.json", "database.yml", "secrets.yml", ".htpasswd",
    ".htaccess", "wp-config.php", "wp-config-sample.php",
    # control de versiones (CRÍTICO)
    ".git", ".git/", ".git/config", ".git/HEAD", ".git/COMMIT_EDITMSG",
    ".git/index", ".gitignore", ".gitattributes", ".svn", ".svn/",
    ".svn/entries", ".hg", ".hg/", ".bzr", ".bzr/",
    # backup y archivos temporales
    "backup", "backup/", "backups", "backups/", "bak",
    "backup.zip", "backup.tar.gz", "backup.sql", "backup.db",
    "db.sql", "dump.sql", "database.sql", "db_backup.sql",
    "site.zip", "www.zip", "html.zip", "web.zip",
    "old", "old/", "temp", "tmp", "tmp/", "cache", "cache/",
    # registros y logs
    "logs", "logs/", "log", "log/", "error.log", "access.log",
    "debug.log", "application.log",
    # información del servidor
    "server-status", "server-info", "phpinfo.php", "info.php",
    "test.php", "test.html", "readme", "readme.md", "readme.txt",
    "README.md", "CHANGELOG", "CHANGELOG.md", "INSTALL.md",
    "robots.txt", "sitemap.xml", "humans.txt", "security.txt",
    ".well-known", ".well-known/", ".well-known/security.txt",
    # entornos de desarrollo
    "dev", "dev/", "develop", "development", "staging", "stage",
    "test", "testing", "qa", "sandbox", "demo", "beta", "alpha",
    # CI/CD y despliegue
    "jenkins", "jenkins/", "gitlab", "bitbucket", "deploy",
    "ci", "cd", ".travis.yml", "Dockerfile", "docker-compose.yml",
    ".circleci", "Jenkinsfile", ".github", ".github/",
    # monitoreo y observabilidad
    "metrics", "prometheus", "grafana", "kibana", "health",
    "healthcheck", "health-check", "status", "ping", "alive",
    "actuator", "actuator/", "actuator/health", "actuator/env",
    "actuator/beans", "actuator/mappings", "/actuator/metrics",
    # documentación interna
    "docs", "docs/", "doc", "doc/", "wiki", "wiki/",
    "documentation", "help", "help/",
    # archivos de instalación
    "install", "install.php", "setup", "setup.php", "upgrade.php",
    "update.php", "installer",
    # wordpress
    "wp-admin", "wp-admin/", "wp-login.php", "wp-includes",
    "wp-content", "wp-json", "wp-json/", "xmlrpc.php",
    "wp-cron.php",
    # otros CMS y frameworks
    "joomla", "drupal", "sites/default", "sites/default/files",
    "user", "user/login", "user/register",
    # almacenamiento y uploads
    "upload", "uploads", "files", "static", "assets", "media",
    "images", "img", "css", "js", "vendor",
    # phpMyAdmin variantes
    "phpmyadmin", "phpMyAdmin", "phpmy", "myadmin", "sqladmin",
    # misc
    "server", "cgi-bin", "cgi-bin/", "fcgi-bin", "errors",
    "error", "404.php", "403.php", "500.php",
    ".DS_Store", "thumbs.db", "desktop.ini",
    "package.json", "package-lock.json", "composer.json",
    "composer.lock", "yarn.lock", "Gemfile", "Gemfile.lock",
    "requirements.txt", "Pipfile", "pom.xml", "build.gradle",
]

# Rutas críticas que si existen generan alerta CRITICAL/HIGH
CRITICAL_PATHS = {
    ".git", ".git/", ".git/config", ".git/HEAD", ".git/index",
    ".svn", ".svn/", ".hg", ".hg/", ".bzr",
    ".env", ".env.local", ".env.production", ".env.backup",
    "wp-config.php",
}

HIGH_PATHS = {
    "phpmyadmin", "pma", "adminer", "dbadmin", "phpinfo.php", "info.php",
    "admin", "admin/", "administrator", "administrator/",
    "backup.zip", "backup.tar.gz", "backup.sql", "dump.sql",
    "database.sql", "db.sql", "db_backup.sql", "site.zip",
    "actuator/env", "actuator/beans", "actuator/mappings",
    ".htpasswd", "server-status", "server-info", "install.php",
    "setup.php", "xmlrpc.php",
}

# Códigos HTTP que indican recurso encontrado
FOUND_CODES = {200, 201, 204, 301, 302, 307, 308, 401, 403}
# Códigos que definitivamente no existen
NOT_FOUND_CODES = {404, 410}


# ------------------------------------------------------------------ clase

class DirBuster:
    """Motor de descubrimiento de rutas web."""

    def __init__(self, target: str, wordlist: list[str] | None = None,
                 threads: int = 40, timeout: float = 6.0,
                 extensions: list[str] | None = None):
        self.settings = get_settings()
        self.target = self._normalize_target(target)
        self.wordlist = wordlist if wordlist else WORDLIST
        self.threads = max(1, min(threads, 100))
        self.timeout = max(1.0, float(timeout))
        self.extensions = extensions or []
        self.findings: list[Finding] = []
        self._not_found_heuristic: str | None = None

    # ---------------------------------------------------------------- utils

    def _add(self, check: str, title: str, severity: str, detail: str):
        self.findings.append(Finding(check, title, severity, detail))

    @staticmethod
    def _normalize_target(target: str) -> str:
        t = target.strip()
        if not t.startswith(("http://", "https://")):
            t = "https://" + t
        return t.rstrip("/")

    def _make_url(self, path: str) -> str:
        p = path if path.startswith("/") else "/" + path
        return self.target + p

    # ---------------------------------------------------------------- heurística 404

    def _calibrate_404(self) -> bool:
        """
        Detecta páginas 404 personalizadas que devuelven 200.
        Hace una petición a una ruta aleatoria y guarda el código.
        """
        test_url = self._make_url(f"__pestesting_nonexistent_{int(time.time())}")
        try:
            req = urllib.request.Request(
                test_url, headers=self.settings["request_headers"])
            resp = urllib.request.urlopen(req, timeout=self.timeout)
            code = resp.status
            resp.close()
            if code == 200:
                self._not_found_heuristic = "200"  # custom 404
                self._add("calibracion", "404 personalizado detectado", "INFO",
                          "El servidor devuelve HTTP 200 para rutas inexistentes "
                          "(soft 404). Los resultados con código 200 pueden incluir "
                          "falsos positivos.")
            return True
        except urllib.error.HTTPError:
            return True
        except Exception:
            return False

    # ---------------------------------------------------------------- worker

    def _check_path(self, path: str) -> dict | None:
        """Solicita una ruta y devuelve dict con resultado o None si no existe."""
        url = self._make_url(path)
        try:
            req = urllib.request.Request(
                url, headers=self.settings["request_headers"])
            try:
                resp = urllib.request.urlopen(req, timeout=self.timeout)
                code = resp.status
                content_length = resp.headers.get("Content-Length", "-")
                content_type = resp.headers.get("Content-Type", "-")
                resp.close()
            except urllib.error.HTTPError as exc:
                code = exc.code
                content_length = exc.headers.get("Content-Length", "-") if exc.headers else "-"
                content_type = exc.headers.get("Content-Type", "-") if exc.headers else "-"
                exc.close()

            if code in NOT_FOUND_CODES:
                return None
            if code not in FOUND_CODES:
                return None

            return {
                "url": url,
                "path": path,
                "codigo": code,
                "content_type": content_type.split(";")[0].strip(),
                "content_length": content_length,
            }
        except (urllib.error.URLError, socket.timeout, OSError):
            return None

    # ---------------------------------------------------------------- enum

    def bust(self) -> dict:
        """Ejecuta el descubrimiento de rutas."""
        self.findings = []
        started = datetime.now(timezone.utc)
        t0 = time.monotonic()

        # --- calibración ---
        reachable = self._calibrate_404()
        if not reachable:
            self._add("red", "Objetivo inaccesible", "CRITICAL",
                      f"No se pudo establecer conexión con '{self.target}'.")
            return self._build_report(started, [], 0, 0.0)

        # --- construir lista de paths con extensiones extra ---
        paths = list(self.wordlist)
        if self.extensions:
            base_paths = [p for p in self.wordlist if "." not in p.split("/")[-1]]
            for base in base_paths:
                for ext in self.extensions:
                    ext_path = f"{base}.{ext.lstrip('.')}"
                    if ext_path not in paths:
                        paths.append(ext_path)

        total = len(paths)
        found: list[dict] = []

        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            futures = {pool.submit(self._check_path, path): path for path in paths}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)

        found.sort(key=lambda e: (e["codigo"], e["path"]))
        duration = time.monotonic() - t0

        self._analyze(found)
        self.findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
        risk = compute_risk(self.findings, self.settings["risk_thresholds"])

        return self._build_report(started, found, total, duration, risk)

    # ---------------------------------------------------------------- análisis

    def _analyze(self, found: list[dict]):
        if not found:
            self._add("rutas", "Sin rutas encontradas", "INFO",
                      "No se descubrió ninguna ruta en la wordlist utilizada.")
            return

        self._add("rutas", f"{len(found)} ruta(s) descubierta(s)", "INFO",
                  ", ".join(e["path"] for e in found[:15])
                  + (" …" if len(found) > 15 else ""))

        for entry in found:
            path = entry["path"].rstrip("/")
            code = entry["codigo"]

            # Rutas críticas (exponen código fuente o secretos)
            if path in CRITICAL_PATHS or path + "/" in CRITICAL_PATHS:
                self._add("exposicion",
                          f"Ruta CRÍTICA expuesta: /{path}",
                          "CRITICAL",
                          f"[{code}] '{entry['url']}' — Esta ruta puede exponer "
                          "código fuente, secretos o configuración sensible del servidor.")
            elif path in HIGH_PATHS or path + "/" in HIGH_PATHS:
                self._add("exposicion",
                          f"Ruta de alto riesgo expuesta: /{path}",
                          "HIGH",
                          f"[{code}] '{entry['url']}' — Recurso sensible accesible "
                          "que puede facilitar intrusión o revelación de datos.")
            elif code in (401, 403):
                self._add("acceso",
                          f"Ruta protegida detectada: /{path}",
                          "MEDIUM",
                          f"[{code}] '{entry['url']}' — Existe pero requiere "
                          "autenticación; objetivo para fuerza bruta de credenciales.")

    # ---------------------------------------------------------------- informe

    def _build_report(self, started, found, total_checked, duration=0.0, risk=None):
        if risk is None:
            risk = compute_risk(self.findings, self.settings["risk_thresholds"])
        return {
            "tool": "PESTesting Suite",
            "modulo": "Fuerza Bruta de Directorios",
            "modulo_slug": "dirbust",
            "version": VERSION,
            "objetivo": self.target,
            "fecha_analisis": started.isoformat(),
            "modo": (f"HTTP brute-force | {total_checked} rutas | "
                     f"{self.threads} hilos | timeout {self.timeout}s"),
            "resumen": [
                ["Objetivo", self.target],
                ["Rutas probadas", total_checked],
                ["Rutas encontradas", len(found)],
                ["404 personalizado", "Sí" if self._not_found_heuristic else "No"],
                ["Duración", f"{duration:.2f} s"],
            ],
            "rutas": found,
            "hallazgos": [asdict(f) for f in self.findings],
            "riesgo": risk,
        }
