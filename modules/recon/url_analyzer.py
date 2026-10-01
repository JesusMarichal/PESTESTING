# -*- coding: utf-8 -*-
"""
Analizador de URLs (módulo de reconocimiento).

Comprobaciones realizadas:
- Estructura y componentes de la URL (esquema, host, puerto, ruta, query...)
- Uso de HTTPS, credenciales embebidas y esquemas inusuales
- IP directa (pública/privada), puertos no estándar, TLD sospechosos
- Acortadores de URL, dominios IDN/punycode y homoglyphs
- Typosquatting / suplantación de marcas conocidas
- Palabras clave típicas de phishing y descargas de ejecutables
- Resolución DNS, registro PTR
- Cadena de redirecciones HTTP y cabeceras de seguridad
- Estado del certificado TLS (validez, emisor, caducidad, protocolo)
"""

import ipaddress
import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

from core.config import get_settings

RISK_POINTS = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 4, "INFO": 1, "OK": 0}
SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "OK"]
SEVERITY_ORDER = {name: idx for idx, name in enumerate(SEVERITIES)}

LEET_MAP = {
    "a": "a4@",
    "b": "b8",
    "e": "e3",
    "g": "g9",
    "i": "i1l|!",
    "l": "l1|i",
    "o": "o0",
    "s": "s5$",
    "t": "t7",
}

DANGEROUS_EXTENSIONS = (
    ".exe", ".scr", ".bat", ".cmd", ".jar", ".apk", ".msi", ".vbs", ".ps1", ".hta"
)

ENGLISH_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


@dataclass
class Finding:
    check: str
    title: str
    severity: str
    detail: str


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Evita que urllib siga redirecciones automáticamente (para trazarlas)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _leet_variants(word):
    """Genera las variantes 'leet' posibles de una palabra (g00gle, paypa1...)."""
    variants = {""}
    for ch in word.lower():
        options = LEET_MAP.get(ch, ch)
        variants = {v + o for v in variants for o in options}
    return variants


def _parse_cert_date(text):
    """Parsea fechas de certificado ('Jun 26 12:00:00 2026 GMT') sin depender del locale."""
    try:
        parts = text.split()
        month = ENGLISH_MONTHS[parts[0]]
        day = int(parts[1])
        hh, mm, ss = (int(x) for x in parts[2].split(":"))
        year = int(parts[3])
        return datetime(year, month, day, hh, mm, ss, tzinfo=timezone.utc)
    except (KeyError, IndexError, ValueError):
        return None


class URLAnalyzer:
    """Motor de análisis de URLs."""

    def __init__(self, timeout=8.0, offline=False):
        self.settings = get_settings()
        self.timeout = timeout
        self.offline = offline
        self.findings = []
        self._brand_cache = {}

    # ------------------------------------------------------------------ utils

    def _add(self, check, title, severity, detail):
        self.findings.append(Finding(check, title, severity, detail))

    def _netloc_host(self, host):
        """Convierte el host a su forma ASCII (IDNA) para operaciones de red."""
        if not host:
            return host
        if all(ord(c) < 128 for c in host):
            return host
        try:
            return host.encode("idna").decode("ascii")
        except UnicodeError:
            return host

    def _request_url(self, url):
        """Normaliza una IRI a URI válida (host IDNA, ruta/query quotados)."""
        try:
            parts = urllib.parse.urlsplit(url)
            host = self._netloc_host(parts.hostname or "")
            try:
                port = parts.port
            except ValueError:
                port = None
            netloc = host + (f":{port}" if port else "")
            path = urllib.parse.quote(parts.path, safe="/%:@!$&'()*+,;=-._~")
            query = urllib.parse.quote(parts.query, safe="=&%:@!$&'()*+,;?-._~")
            return urllib.parse.urlunsplit((parts.scheme, netloc, path, query, parts.fragment))
        except ValueError:
            return url

    # ------------------------------------------------------------- análisis

    def analyze(self, url):
        self.findings = []
        analyzed_at = datetime.now(timezone.utc)
        original = url.strip()
        normalized = original

        if not re.match(r"^[A-Za-z][A-Za-z0-9+.\-]*://", normalized):
            normalized = "http://" + normalized

        parsed = urllib.parse.urlsplit(normalized)
        host = (parsed.hostname or "").lower()

        try:
            port = parsed.port
        except ValueError:
            port = None
            self._add("estructura", "Puerto inválido", "MEDIUM",
                      "La URL declara un puerto con un valor no válido.")

        structure = {
            "url_original": original,
            "url_normalizada": normalized,
            "esquema": parsed.scheme,
            "host": host,
            "puerto": port,
            "ruta": parsed.path,
            "query": parsed.query,
            "fragmento": parsed.fragment,
            "usuario": parsed.username,
            "password": "***" if parsed.password else None,
            "parametros": dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
            if parsed.query else {},
            "etiquetas_host": host.split(".") if host else [],
            "profundidad_ruta": len([p for p in parsed.path.split("/") if p]),
            "longitud_url": len(normalized),
        }

        network = {"enabled": False}
        http = {"enabled": False}
        tls = {"enabled": False}

        if not host:
            self._add("estructura", "URL sin host válido", "CRITICAL",
                      "No se pudo extraer un host de la URL proporcionada.")
        else:
            self._check_scheme(parsed)
            self._check_credentials(parsed, host)
            self._check_structure(normalized, parsed, host, port, structure)
            self._check_host(host, port)
            self._check_brands(host)
            self._check_phishing_keywords(normalized, parsed)

            if not self.offline and parsed.scheme in ("http", "https"):
                net_host = self._netloc_host(host)
                network = self._check_dns(net_host)
                http = self._check_http(normalized)
                if parsed.scheme == "https":
                    tls = self._check_tls(net_host, port or 443)

        self.findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
        risk = self._compute_risk()

        return {
            "tool": "PESTesting Suite",
            "modulo": "Analisis de URL",
            "version": "0.1.0",
            "objetivo": original,
            "fecha_analisis": analyzed_at.isoformat(),
            "modo": "offline (sin comprobaciones de red)" if self.offline else "completo",
            "estructura": structure,
            "red": network,
            "http": http,
            "tls": tls,
            "hallazgos": [asdict(f) for f in self.findings],
            "riesgo": risk,
        }

    # -------------------------------------------------------- comprobaciones

    def _check_scheme(self, parsed):
        if parsed.scheme not in ("http", "https"):
            self._add("esquema", "Esquema de URL inusual", "MEDIUM",
                      f"La URL usa el esquema '{parsed.scheme}', no estándar para navegación web.")
        elif parsed.scheme != "https":
            self._add("esquema", "La URL no usa HTTPS", "MEDIUM",
                      "El tráfico viaja sin cifrar; un atacante en la red puede interceptarlo (sniffing/MITM).")
        else:
            self._add("esquema", "La URL usa HTTPS", "OK",
                      "El transporte está cifrado con TLS.")

    def _check_credentials(self, parsed, host):
        if parsed.username:
            cred = parsed.username + (":***" if parsed.password else "")
            self._add("credenciales", "Credenciales embebidas en la URL", "CRITICAL",
                      f"La URL contiene credenciales ('{cred}@{host}'). "
                      "Técnica clásica de phishing para ocultar el host real ante el usuario.")
        if parsed.password:
            self._add("credenciales", "Contraseña en texto claro en la URL", "HIGH",
                      "La contraseña viaja visible en la URL (quedará en historiales y logs).")

    def _check_structure(self, url, parsed, host, port, structure):
        length = structure["longitud_url"]
        if length >= 100:
            self._add("estructura", "URL extremadamente larga", "MEDIUM",
                      f"La URL mide {length} caracteres; habitual en phishing para ocultar el destino real.")
        elif length >= 75:
            self._add("estructura", "URL larga", "LOW",
                      f"La URL mide {length} caracteres.")

        depth = structure["profundidad_ruta"]
        if depth > 4:
            self._add("estructura", "Ruta excesivamente profunda", "INFO",
                      f"La ruta tiene {depth} niveles; técnica común para aparentar legitimidad.")

        path = (parsed.path or "").lower()
        for ext in DANGEROUS_EXTENSIONS:
            if path.endswith(ext):
                self._add("estructura", "Posible descarga de ejecutable", "MEDIUM",
                          f"La ruta termina en '{ext}', un archivo potencialmente ejecutable/malicioso.")
                break

        if structure["parametros"]:
            self._add("estructura", "Parámetros en la query", "INFO",
                      f"La URL incluye {len(structure['parametros'])} parámetro(s); "
                      "revisar inyecciones (SQL/XSS/SSRF) en los valores.")

        if port is not None:
            if port not in self.settings["common_ports"]:
                self._add("estructura", "Puerto no estándar", "MEDIUM",
                          f"La URL usa el puerto {port}, poco habitual en servicios web públicos.")
            elif port not in self.settings["standard_ports"]:
                self._add("estructura", "Puerto alternativo habitual", "LOW",
                          f"La URL usa el puerto {port} (alternativo común, p. ej. proxy o dev).")

    def _check_host(self, host, port):
        is_ip = re.match(r"^(\d{1,3}\.){3}\d{1,3}$", host) or ":" in host
        if is_ip:
            try:
                addr = ipaddress.ip_address(host)
                if addr.is_loopback:
                    self._add("host", "IP de loopback", "INFO",
                              f"La URL apunta a {host} (localhost).")
                elif addr.is_private:
                    self._add("host", "IP privada (red interna)", "INFO",
                              f"La URL apunta a {host}, una dirección privada (RFC1918). "
                              "Relevante para detectar servicios internos expuestos.")
                else:
                    self._add("host", "La URL apunta a una IP directa", "MEDIUM",
                              f"La URL apunta directamente a {host} en lugar de a un dominio; "
                              "típico de phishing o infraestructura sin dominio.")
            except ValueError:
                self._add("host", "Formato de IP inválido", "MEDIUM",
                          f"'{host}' parece una IP pero tiene un formato incorrecto.")

        labels = host.split(".")
        tld = labels[-1] if labels and not is_ip else ""

        if tld in self.settings["suspicious_tlds"]:
            self._add("host", "TLD de alto riesgo", "MEDIUM",
                      f"El TLD '.{tld}' se asocia con frecuencia a campañas de malware y phishing.")

        for shortener in self.settings["shorteners"]:
            if host == shortener or host.endswith("." + shortener):
                self._add("host", "Acortador de URL detectado", "MEDIUM",
                          f"'{host}' es un servicio acortador; el destino real permanece oculto "
                          "hasta resolver la redirección.")
                break

        if "xn--" in host:
            decoded = []
            for label in labels:
                try:
                    decoded.append(label.encode("ascii").decode("idna") if label.startswith("xn--") else label)
                except UnicodeError:
                    decoded.append(label)
            self._add("host", "Dominio IDN/punycode", "MEDIUM",
                      f"El host usa punycode ('{host}' = '{'.'.join(decoded)}'); "
                      "posible ataque homoglyph (p. ej. 'rn' en lugar de 'm').")

        if not is_ip and host and any(ord(c) > 127 for c in host):
            try:
                ascii_host = host.encode("idna").decode("ascii")
                self._add("host", "Dominio con caracteres Unicode", "MEDIUM",
                          f"El host contiene caracteres no ASCII ('{host}' -> '{ascii_host}'); "
                          "riesgo de suplantación visual (homoglyphs).")
            except UnicodeError:
                pass

        if host.count("-") >= 3:
            self._add("host", "Exceso de guiones en el host", "LOW",
                      f"El host '{host}' contiene {host.count('-')} guiones; patrón habitual en phishing.")

        if len(labels) >= 6:
            self._add("host", "Demasiados subdominios", "LOW",
                      f"El host tiene {len(labels)} etiquetas ({host}); "
                      "técnica para diluir la parte sospechosa del dominio.")

    def _check_brands(self, host):
        labels = host.split(".")
        if len(labels) < 2 or re.match(r"^(\d{1,3}\.){3}\d{1,3}$", host):
            return
        registrable = ".".join(labels[-2:])

        for brand, official in self.settings["known_brands"].items():
            if host == official or host.endswith("." + official):
                self._add("marca", f"Dominio oficial de {brand}", "OK",
                          f"'{host}' pertenece al dominio oficial '{official}'.")
                continue
            if brand not in self._brand_cache:
                self._brand_cache[brand] = _leet_variants(brand)
            variants = self._brand_cache[brand]
            for label in labels[:-1]:
                stripped = re.sub(r"[-_]", "", label)
                parts = [p for p in re.split(r"[-_]", label) if p]
                if label == brand or stripped == brand or brand in parts:
                    self._add("marca", f"Marca '{brand}' en dominio no oficial", "MEDIUM",
                              f"El host contiene la marca '{brand}' pero el dominio registrable es "
                              f"'{registrable}' (oficial: '{official}'). Posible domain squatting.")
                    break
                if any(v != brand and v in stripped for v in variants):
                    self._add("marca", f"Posible typosquatting de '{brand}'", "HIGH",
                              f"La etiqueta '{label}' imita a '{brand}' con sustituciones de caracteres "
                              f"(leet/homoglyph). Dominio oficial: '{official}'.")
                    break

    def _check_phishing_keywords(self, url, parsed):
        haystack = (url or "").lower()
        matches = [kw for kw in self.settings["phishing_keywords"] if kw in haystack]
        if matches:
            self._add("phishing", "Palabras clave típicas de phishing", "LOW",
                      f"Coincidencias: {', '.join(matches)}. Contexto habitual de páginas de robo "
                      "de credenciales; combinar con el resto de señales.")

    def _check_dns(self, host):
        data = {"enabled": True}
        if not host:
            return data
        try:
            infos = socket.getaddrinfo(host, None)
            ips = sorted({i[4][0] for i in infos})
        except socket.gaierror as exc:
            self._add("dns", "Resolución DNS fallida", "HIGH",
                      f"No se pudo resolver '{host}': {exc}. El dominio podría no existir.")
            data["resuelve"] = False
            return data

        ipv4 = [ip for ip in ips if ":" not in ip]
        ipv6 = [ip for ip in ips if ":" in ip]
        data.update({"resuelve": True, "ipv4": ipv4, "ipv6": ipv6})
        self._add("dns", "Resolución DNS correcta", "OK",
                  f"{host} -> {', '.join(ips[:5])}")

        try:
            first = ipaddress.ip_address(ipv4[0] if ipv4 else ips[0])
            if first.is_private or first.is_loopback:
                data["red_privada"] = True
                self._add("dns", "IP privada o interna", "INFO",
                          f"La URL resuelve a {first} (red interna/loopback).")
        except ValueError:
            pass

        try:
            ptr = socket.gethostbyaddr(ipv4[0] if ipv4 else ips[0])[0]
            data["ptr"] = ptr
        except (socket.herror, OSError):
            data["ptr"] = None
        return data

    def _check_http(self, url):
        data = {"enabled": True, "redirecciones": []}
        opener = urllib.request.build_opener(_NoRedirectHandler())
        current = self._request_url(url)
        visited = set()
        final_headers = None
        final_status = None
        hops = 0

        try:
            while hops < 10:
                hops += 1
                if current in visited:
                    self._add("http", "Bucle de redirecciones", "MEDIUM",
                              f"La cadena de redirecciones vuelve a '{current}'.")
                    break
                visited.add(current)
                req = urllib.request.Request(current, headers=self.settings["request_headers"])
                try:
                    resp = opener.open(req, timeout=self.timeout)
                    status, headers = resp.status, resp.headers
                    resp.close()
                except urllib.error.HTTPError as exc:
                    status, headers = exc.code, exc.headers
                    exc.close()

                if status in (301, 302, 303, 307, 308):
                    location = headers.get("Location") or ""
                    target = urllib.parse.urljoin(current, location)
                    data["redirecciones"].append({"desde": current, "estado": status, "a": target})
                    if target.startswith("http://") and current.startswith("https://"):
                        self._add("http", "Redirección de HTTPS a HTTP", "HIGH",
                                  f"'{current}' redirige a '{target}' degradando el cifrado.")
                    current = target
                    continue
                final_status, final_headers = status, headers
                break
            else:
                self._add("http", "Demasiadas redirecciones", "HIGH",
                          "La URL supera 10 redirecciones seguidas (posible ofuscación).")
        except (urllib.error.URLError, socket.timeout, OSError) as exc:
            reason = getattr(exc, "reason", exc)
            self._add("http", "Host HTTP inaccesible", "HIGH",
                      f"No se pudo completar la petición HTTP: {reason}")
            data["error"] = str(reason)
            return data

        data.update({"estado_final": final_status, "url_final": current})
        if final_headers is not None:
            data["cabeceras"] = dict(final_headers.items())
            self._check_security_headers(final_headers)

        if data["redirecciones"]:
            first = data["redirecciones"][0]["desde"]
            if urllib.parse.urlsplit(first).hostname != urllib.parse.urlsplit(current).hostname:
                self._add("http", "Redirección a otro dominio", "INFO",
                          f"La URL acaba sirviéndose desde '{urllib.parse.urlsplit(current).hostname}'.")
        return data

    def _check_security_headers(self, headers):
        missing = [h for h in self.settings["security_headers"] if not headers.get(h)]
        if missing:
            self._add("cabeceras", "Cabeceras de seguridad ausentes", "MEDIUM",
                      "Faltan: " + ", ".join(missing) + ". Incrementan la exposición a XSS, "
                      "clickjacking y MIME sniffing.")
        else:
            self._add("cabeceras", "Cabeceras de seguridad presentes", "OK",
                      "Se detectaron las cabeceras de seguridad recomendadas.")

        server = headers.get("Server")
        if server:
            severity = "INFO" if "/" not in server else "LOW"
            self._add("cabeceras", "Servidor revelado en cabeceras", severity,
                      f"La cabecera 'Server' expone: '{server}'. Facilita el fingerprinting.")

        powered = headers.get("X-Powered-By")
        if powered:
            self._add("cabeceras", "Tecnología revelada", "LOW",
                      f"La cabecera 'X-Powered-By' expone: '{powered}'.")

        cookies = headers.get_all("Set-Cookie") or []
        insecure = []
        for cookie in cookies:
            name = cookie.split("=", 1)[0].strip()
            flags = cookie.lower()
            if "httponly" not in flags or "secure" not in flags:
                insecure.append(f"{name} (HttpOnly: {'httponly' in flags}, Secure: {'secure' in flags})")
        if insecure:
            self._add("cabeceras", "Cookies sin flags de seguridad", "LOW",
                      f"{len(insecure)} cookie(s) sin 'Secure'/'HttpOnly': " + "; ".join(insecure[:5]))

    def _check_tls(self, host, port):
        data = {"enabled": True, "host": host, "puerto": port}
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as tls:
                    cert = tls.getpeercert()
                    data["protocolo"] = tls.version()
                    cipher = tls.cipher()
                    data["cifrado"] = cipher[0] if cipher else None
        except ssl.SSLCertVerificationError as exc:
            self._add("tls", "Certificado TLS inválido o no confiable", "CRITICAL",
                      f"{exc.verify_message if hasattr(exc, 'verify_message') else exc} "
                      "(caducado, emisor desconocido o hostname no coincide).")
            return data
        except (ssl.SSLError, OSError) as exc:
            self._add("tls", "Fallo en la conexión TLS", "HIGH", f"No se pudo negociar TLS: {exc}")
            return data

        def _flatten_name(rdn_sequence):
            return ", ".join(f"{key}={value}"
                            for rdn in rdn_sequence for key, value in rdn)

        issuer = _flatten_name(cert.get("issuer", ()))
        subject = _flatten_name(cert.get("subject", ()))
        data.update({"emisor": issuer, "sujeto": subject})

        san = cert.get("subjectAltName") or []
        data["num_san"] = len(san)

        not_after = _parse_cert_date(cert.get("notAfter", ""))
        if not_after:
            data["expira"] = not_after.isoformat()
            days_left = (not_after - datetime.now(timezone.utc)).days
            if days_left < 0:
                self._add("tls", "Certificado caducado", "CRITICAL",
                          f"El certificado expiró hace {-days_left} día(s) ({not_after:%Y-%m-%d}).")
            elif days_left < 15:
                self._add("tls", "Certificado a punto de caducar", "HIGH",
                          f"El certificado expira en {days_left} día(s) ({not_after:%Y-%m-%d}).")
            else:
                self._add("tls", "Certificado TLS válido", "OK",
                          f"Emisor: {issuer or 'desconocido'} | Expira: {not_after:%Y-%m-%d} "
                          f"({days_left} días) | SAN: {len(san)} entradas.")

        if data.get("protocolo") in ("TLSv1", "TLSv1.1"):
            self._add("tls", "Protocolo TLS obsoleto", "MEDIUM",
                      f"El servidor negocia {data['protocolo']}, considerado inseguro (debería usar TLS >= 1.2).")

        if not san:
            self._add("tls", "Certificado sin Subject Alternative Names", "LOW",
                      "El certificado no declara SANs; los navegadores modernos requieren esta extensión.")
        return data

    # ------------------------------------------------------------- riesgo

    def _compute_risk(self):
        thresholds = self.settings["risk_thresholds"]
        total = sum(RISK_POINTS.get(f.severity, 0) for f in self.findings)
        score = min(total, 100)
        if score < thresholds["bajo"]:
            level = "BAJO"
        elif score < thresholds["medio"]:
            level = "MEDIO"
        elif score < thresholds["alto"]:
            level = "ALTO"
        else:
            level = "CRITICO"

        summary = {s: sum(1 for f in self.findings if f.severity == s) for s in SEVERITIES}
        return {
            "puntuacion": score,
            "nivel": level,
            "resumen": summary,
            "total_hallazgos": len(self.findings),
        }
