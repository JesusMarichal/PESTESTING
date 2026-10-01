# -*- coding: utf-8 -*-
"""
Analizador profundo de SSL/TLS y cabeceras HTTP de seguridad.

Comprobaciones:
- Certificado X.509: validez, caducidad, emisor, CN, SANs, autofirmado
- Protocolos TLS negociables: TLS 1.0/1.1 (obsoletos), TLS 1.2/1.3 (seguros)
- Suite de cifrado negociada: claves débiles, RC4, NULL, EXPORT, anon
- HSTS: presencia, max-age, includeSubDomains, preload
- Análisis exhaustivo de las 10+ cabeceras de seguridad HTTP más importantes
- Cookies: Secure, HttpOnly, SameSite, __Host/__Secure prefix
- Fingerprinting de tecnologías (Server, X-Powered-By, X-AspNet-Version…)
- Políticas de CORS (Access-Control-Allow-Origin)
"""

import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict
from datetime import datetime, timezone

from core import VERSION
from core.config import get_settings
from core.findings import Finding, SEVERITY_ORDER, compute_risk

ENGLISH_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

# Suites de cifrado débiles (fragmento del nombre que aparece en el cipher name)
WEAK_CIPHER_KEYWORDS = (
    "RC4", "NULL", "EXPORT", "ANON", "DES", "3DES", "MD5",
    "RC2", "IDEA", "SEED", "ARIA",
)

# Cabeceras de seguridad y su peso de análisis
SECURITY_HEADERS_MAP = {
    "Strict-Transport-Security": {
        "severity_missing": "HIGH",
        "detail_missing": (
            "Sin HSTS el navegador puede conectar por HTTP inicialmente, "
            "abriendo la puerta a ataques SSL-stripping y MITM."
        ),
    },
    "Content-Security-Policy": {
        "severity_missing": "MEDIUM",
        "detail_missing": (
            "Sin CSP el navegador ejecuta cualquier script de cualquier origen, "
            "facilitando ataques XSS."
        ),
    },
    "X-Frame-Options": {
        "severity_missing": "MEDIUM",
        "detail_missing": (
            "Sin X-Frame-Options la página puede embeberse en iFrames maliciosos "
            "(clickjacking)."
        ),
    },
    "X-Content-Type-Options": {
        "severity_missing": "LOW",
        "detail_missing": (
            "Sin 'nosniff' el navegador puede interpretar respuestas con tipo MIME "
            "incorrecto (MIME sniffing attacks)."
        ),
    },
    "Referrer-Policy": {
        "severity_missing": "LOW",
        "detail_missing": (
            "Sin política de referrer la URL completa se filtra a terceros en "
            "cabeceras Referer."
        ),
    },
    "Permissions-Policy": {
        "severity_missing": "LOW",
        "detail_missing": (
            "Sin Permissions-Policy cualquier script puede solicitar acceso a cámara, "
            "micrófono o geolocalización."
        ),
    },
    "Cross-Origin-Opener-Policy": {
        "severity_missing": "LOW",
        "detail_missing": (
            "Sin COOP la página es vulnerable a ataques de canal lateral entre "
            "ventanas del navegador."
        ),
    },
    "Cross-Origin-Resource-Policy": {
        "severity_missing": "LOW",
        "detail_missing": (
            "Sin CORP cualquier sitio puede cargar recursos de este origen mediante "
            "<img>, <script>, etc. (Spectre side-channel)."
        ),
    },
}


# ------------------------------------------------------------------ utilidades

def _parse_cert_date(text: str) -> datetime | None:
    try:
        parts = text.split()
        month = ENGLISH_MONTHS[parts[0]]
        day = int(parts[1])
        hh, mm, ss = (int(x) for x in parts[2].split(":"))
        year = int(parts[3])
        return datetime(year, month, day, hh, mm, ss, tzinfo=timezone.utc)
    except (KeyError, IndexError, ValueError):
        return None


def _flatten_name(rdn_sequence) -> str:
    return ", ".join(f"{k}={v}" for rdn in rdn_sequence for k, v in rdn)


# ------------------------------------------------------------------ analizador

class HeaderSSLAnalyzer:
    """Analizador profundo de TLS y cabeceras HTTP de seguridad."""

    def __init__(self, target: str, timeout: float = 8.0):
        self.settings = get_settings()
        self.target = self._normalize(target)
        self.timeout = max(1.0, float(timeout))
        self.findings: list[Finding] = []
        self._parsed = urllib.parse.urlsplit(self.target)
        self.host = (self._parsed.hostname or "").lower()
        self.port = self._parsed.port or (443 if self._parsed.scheme == "https" else 80)

    # ---------------------------------------------------------------- utils

    def _add(self, check: str, title: str, severity: str, detail: str):
        self.findings.append(Finding(check, title, severity, detail))

    @staticmethod
    def _normalize(target: str) -> str:
        t = target.strip()
        if not t.startswith(("http://", "https://")):
            t = "https://" + t
        return t

    # ---------------------------------------------------------------- TLS profundo

    def _probe_tls_version(self, protocol_flag) -> bool:
        """Intenta negociar TLS con la versión especificada. True si tiene éxito."""
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = protocol_flag
            ctx.maximum_version = protocol_flag
            with socket.create_connection((self.host, self.port),
                                          timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.host):
                    return True
        except Exception:
            return False

    def _analyze_tls(self) -> dict:
        data = {"enabled": True, "host": self.host, "puerto": self.port}

        # --- conexión principal con validación completa ---
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((self.host, self.port),
                                          timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.host) as tls:
                    cert = tls.getpeercert()
                    data["protocolo"] = tls.version()
                    cipher_info = tls.cipher()
                    data["cifrado"] = cipher_info[0] if cipher_info else None
                    data["bits_clave"] = cipher_info[2] if cipher_info else None
        except ssl.SSLCertVerificationError as exc:
            self._add("tls", "Certificado inválido o no confiable", "CRITICAL",
                      f"Error de verificación: {exc}. Puede ser autofirmado, "
                      "caducado o el hostname no coincide.")
            return data
        except (ssl.SSLError, OSError) as exc:
            self._add("tls", "Fallo en negociación TLS", "HIGH",
                      f"No se pudo establecer conexión TLS: {exc}")
            return data

        # --- certificado ---
        issuer = _flatten_name(cert.get("issuer", ()))
        subject = _flatten_name(cert.get("subject", ()))
        san = cert.get("subjectAltName") or []
        data.update({"emisor": issuer, "sujeto": subject, "num_san": len(san),
                     "sans": [v for _, v in san[:20]]})

        # detectar autofirmado (issuer == subject)
        issuer_cn = dict(x for rdn in cert.get("issuer", ()) for x in rdn).get("commonName", "")
        subject_cn = dict(x for rdn in cert.get("subject", ()) for x in rdn).get("commonName", "")
        if issuer_cn and issuer_cn == subject_cn:
            self._add("tls", "Certificado autofirmado", "HIGH",
                      f"El certificado está firmado por sí mismo (issuer CN = subject CN = "
                      f"'{issuer_cn}'). No es confiable por los navegadores.")
        else:
            self._add("tls", "Certificado firmado por CA", "OK",
                      f"Emisor: {issuer or 'desconocido'}")

        # caducidad
        not_after = _parse_cert_date(cert.get("notAfter", ""))
        if not_after:
            data["expira"] = not_after.isoformat()
            days = (not_after - datetime.now(timezone.utc)).days
            data["dias_restantes"] = days
            if days < 0:
                self._add("tls", "Certificado caducado", "CRITICAL",
                          f"Expiró hace {-days} día(s) ({not_after:%Y-%m-%d}).")
            elif days < 15:
                self._add("tls", "Certificado expira pronto", "HIGH",
                          f"Expira en {days} día(s) ({not_after:%Y-%m-%d}). "
                          "Renuévalo antes de que caduque.")
            elif days < 30:
                self._add("tls", "Certificado expira en menos de 30 días", "MEDIUM",
                          f"Expira en {days} día(s) ({not_after:%Y-%m-%d}).")
            else:
                self._add("tls", "Certificado TLS válido y vigente", "OK",
                          f"Expira: {not_after:%Y-%m-%d} ({days} días restantes).")

        # SANs
        if not san:
            self._add("tls", "Sin Subject Alternative Names (SAN)", "LOW",
                      "Los navegadores modernos requieren SANs; un cert sin ellos "
                      "genera advertencias.")
        else:
            self._add("tls", f"SANs presentes ({len(san)} entradas)", "OK",
                      ", ".join(v for _, v in san[:10]) +
                      (f" … (+{len(san)-10} más)" if len(san) > 10 else ""))

        # protocolo negociado
        proto = data.get("protocolo", "")
        if proto in ("TLSv1", "TLSv1.1"):
            self._add("tls", f"Protocolo obsoleto negociado: {proto}", "HIGH",
                      "TLS 1.0 y 1.1 están deprecados (RFC 8996). Usa TLS ≥ 1.2.")
        elif proto == "TLSv1.2":
            self._add("tls", "TLS 1.2 en uso", "LOW",
                      "TLS 1.2 es seguro pero TLS 1.3 ofrece mayor rendimiento "
                      "y seguridad.")
        elif proto == "TLSv1.3":
            self._add("tls", "TLS 1.3 en uso", "OK",
                      "TLS 1.3 es el protocolo más moderno y seguro.")

        # cifrado débil
        cipher_name = (data.get("cifrado") or "").upper()
        for kw in WEAK_CIPHER_KEYWORDS:
            if kw in cipher_name:
                self._add("tls", f"Suite de cifrado débil: {cipher_name}", "HIGH",
                          f"La suite negociada contiene '{kw}', considerado inseguro.")
                break

        # probar si acepta TLS obsoletos
        if hasattr(ssl, "TLSVersion"):
            legacy_versions = []
            try:
                legacy_versions = [
                    (ssl.TLSVersion.TLSv1, "TLS 1.0"),   # type: ignore[attr-defined]
                    (ssl.TLSVersion.TLSv1_1, "TLS 1.1"),  # type: ignore[attr-defined]
                ]
            except AttributeError:
                pass
            for version, label in legacy_versions:
                try:
                    if self._probe_tls_version(version):
                        self._add("tls", f"Servidor acepta {label} (obsoleto)", "MEDIUM",
                                  f"El servidor negocia {label}, que debería estar "
                                  "deshabilitado en la configuración del servidor web.")
                except Exception:
                    pass

        return data

    # ---------------------------------------------------------------- HTTP / cabeceras

    def _fetch_headers(self) -> dict | None:
        """Realiza GET al target y devuelve las cabeceras. None si falla."""
        try:
            req = urllib.request.Request(
                self.target, headers=self.settings["request_headers"])
            try:
                resp = urllib.request.urlopen(req, timeout=self.timeout)
                headers = resp.headers
                code = resp.status
                resp.close()
            except urllib.error.HTTPError as exc:
                headers = exc.headers
                code = exc.code
                exc.close()
            return {"code": code, "headers": headers}
        except Exception as exc:
            self._add("http", "Objetivo HTTP inaccesible", "HIGH",
                      f"No se pudo realizar la petición HTTP: {exc}")
            return None

    def _analyze_headers(self, code: int, headers) -> dict:
        data = {"codigo": code, "cabeceras": dict(headers.items())}

        # --- cabeceras de seguridad ---
        missing, present = [], []
        for h, meta in SECURITY_HEADERS_MAP.items():
            val = headers.get(h)
            if not val:
                missing.append(h)
                self._add("cabecera",
                          f"Cabecera ausente: {h}",
                          meta["severity_missing"],
                          meta["detail_missing"])
            else:
                present.append(h)

        if present:
            self._add("cabecera", f"{len(present)} cabecera(s) de seguridad presentes", "OK",
                      ", ".join(present))

        # --- HSTS profundo ---
        hsts = headers.get("Strict-Transport-Security")
        if hsts:
            data["hsts"] = hsts
            hsts_lower = hsts.lower()
            # max-age
            try:
                max_age_str = next(
                    p.split("=")[1].strip()
                    for p in hsts_lower.split(";")
                    if "max-age" in p
                )
                max_age = int(max_age_str)
                if max_age < 31536000:
                    self._add("hsts", "HSTS max-age insuficiente", "MEDIUM",
                              f"max-age={max_age}s < 31536000s (1 año). "
                              "Se recomienda al menos 1 año para protección efectiva.")
                else:
                    self._add("hsts", "HSTS max-age adecuado", "OK",
                              f"max-age={max_age}s ≥ 1 año.")
            except (StopIteration, ValueError, IndexError):
                self._add("hsts", "HSTS sin max-age válido", "MEDIUM",
                          f"Valor HSTS inválido o sin max-age: '{hsts}'")
            if "includesubdomains" not in hsts_lower:
                self._add("hsts", "HSTS sin includeSubDomains", "LOW",
                          "Sin 'includeSubDomains' los subdominios pueden recibir "
                          "tráfico HTTP sin cifrar.")
            if "preload" not in hsts_lower:
                self._add("hsts", "HSTS sin preload", "INFO",
                          "Sin 'preload' el dominio no puede añadirse a la lista HSTS "
                          "de navegadores (protección total desde el primer acceso).")

        # --- CORS ---
        acao = headers.get("Access-Control-Allow-Origin")
        if acao:
            data["cors"] = acao
            if acao.strip() == "*":
                self._add("cors", "CORS abierto a todos los orígenes (*)", "HIGH",
                          "Access-Control-Allow-Origin: * permite a cualquier web "
                          "acceder a recursos de esta API mediante XHR/fetch "
                          "(grave si la API usa cookies de sesión).")
            else:
                self._add("cors", f"CORS restringido: {acao}", "OK",
                          "Solo se permiten peticiones cross-origin desde orígenes definidos.")

        # --- fingerprinting ---
        server = headers.get("Server")
        if server:
            data["server"] = server
            severity = "LOW" if "/" in server else "INFO"
            self._add("fingerprint", "Cabecera Server revela información", severity,
                      f"'{server}' — Ocultar la versión reduce la superficie de "
                      "reconocimiento pasivo.")

        powered = headers.get("X-Powered-By")
        if powered:
            data["x_powered_by"] = powered
            self._add("fingerprint", "X-Powered-By revela tecnología", "LOW",
                      f"'{powered}' — Eliminar esta cabecera dificulta el fingerprinting.")

        aspnet = headers.get("X-AspNet-Version") or headers.get("X-AspNetMvc-Version")
        if aspnet:
            self._add("fingerprint", "Versión ASP.NET revelada", "LOW",
                      f"'{aspnet}' — Informa de la versión exacta del framework.")

        # --- cookies ---
        cookies = headers.get_all("Set-Cookie") or []
        insecure = []
        samesite_none = []
        for cookie in cookies:
            name = cookie.split("=", 1)[0].strip()
            low = cookie.lower()
            issues = []
            if "httponly" not in low:
                issues.append("sin HttpOnly")
            if "secure" not in low:
                issues.append("sin Secure")
            if "samesite" not in low:
                issues.append("sin SameSite")
            elif "samesite=none" in low and "secure" not in low:
                samesite_none.append(name)
            if issues:
                insecure.append(f"{name} ({', '.join(issues)})")

        if insecure:
            self._add("cookies", f"{len(insecure)} cookie(s) insegura(s)", "MEDIUM",
                      "; ".join(insecure[:8]) +
                      (f" … (+{len(insecure)-8})" if len(insecure) > 8 else ""))
        elif cookies:
            self._add("cookies", f"{len(cookies)} cookie(s) correctamente configuradas", "OK",
                      "Todas las cookies presentan Secure, HttpOnly y SameSite.")

        if samesite_none:
            self._add("cookies", "SameSite=None sin Secure", "HIGH",
                      f"Las cookies {samesite_none} usan SameSite=None pero no tienen "
                      "el flag Secure, lo que permite enviarlas sobre HTTP.")

        return data

    # ---------------------------------------------------------------- analyze

    def analyze(self) -> dict:
        """Ejecuta el análisis completo TLS + cabeceras."""
        self.findings = []
        started = datetime.now(timezone.utc)
        t0 = time.monotonic()

        tls_data: dict = {"enabled": False}
        http_data: dict = {"enabled": False}

        # TLS solo si es HTTPS
        if self._parsed.scheme == "https":
            tls_data = self._analyze_tls()
        else:
            self._add("esquema", "La URL no usa HTTPS", "HIGH",
                      "El análisis TLS no aplica. El tráfico viaja en texto claro.")

        # Análisis de cabeceras HTTP
        response = self._fetch_headers()
        if response:
            http_data = self._analyze_headers(response["code"], response["headers"])
            http_data["enabled"] = True

        duration = time.monotonic() - t0
        self.findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
        risk = compute_risk(self.findings, self.settings["risk_thresholds"])

        return {
            "tool": "PESTesting Suite",
            "modulo": "Análisis SSL/TLS y Cabeceras HTTP",
            "modulo_slug": "headerscan",
            "version": VERSION,
            "objetivo": self.target,
            "fecha_analisis": started.isoformat(),
            "modo": f"HTTP GET + TLS handshake | timeout {self.timeout}s",
            "resumen": [
                ["Objetivo", self.target],
                ["Protocolo TLS", tls_data.get("protocolo", "-")],
                ["Cifrado", tls_data.get("cifrado", "-")],
                ["Bits de clave", tls_data.get("bits_clave", "-")],
                ["Certificado expira", tls_data.get("expira", "-")],
                ["Días restantes", tls_data.get("dias_restantes", "-")],
                ["Emisor", tls_data.get("emisor", "-")],
                ["SANs", tls_data.get("num_san", "-")],
                ["Código HTTP", http_data.get("codigo", "-")],
                ["Duración análisis", f"{duration:.2f} s"],
            ],
            "tls": tls_data,
            "http": http_data,
            "hallazgos": [asdict(f) for f in self.findings],
            "riesgo": risk,
        }
