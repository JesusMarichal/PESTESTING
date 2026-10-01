# Documentación Detallada: PESTesting Suite

Este documento proporciona una explicación exhaustiva de cada término, técnica y métrica evaluada dentro del módulo actual de **PESTesting Suite**. Su propósito es servir como una guía de aprendizaje y referencia técnica.

---

## 1. Módulo `url` (Reconocimiento / Recon)

El objetivo de este módulo es desglosar una URL proporcionada por el usuario y someterla a decenas de pruebas automáticas (estáticas y dinámicas) para determinar su nivel de riesgo. Está diseñado para detectar principalmente campañas de **Phishing**, **Malware** y **Mala configuración de seguridad**.

### 1.1 Estructura de la URL
Antes de enviar una petición a internet, el sistema descompone la URL (modo estático):

*   **Esquema (Scheme):** Define el protocolo. Si es `http://`, se levanta una alerta porque el tráfico viaja en texto plano (sin cifrar). Si es `https://`, indica tráfico cifrado.
*   **Host:** El dominio principal o la dirección IP a la que se intenta acceder (ej. `www.ejemplo.com`).
*   **Puerto (Port):** Puertos estándar son el 80 (HTTP) y 443 (HTTPS). Si la URL usa puertos inusuales (ej. `http://ejemplo.com:8080`), puede ser un indicio de servicios en desarrollo, paneles de control expuestos o infraestructuras temporales atacantes.
*   **Credenciales embebidas:** Si la URL tiene el formato `http://usuario:contraseña@ejemplo.com`, es una práctica obsoleta y peligrosa, a menudo usada en ataques de phishing para confundir a los usuarios y ocultar el host real.
*   **Ruta, Query y Fragmento:** Permite aislar los parámetros (`?id=1`) para futuras pruebas de inyección (SQLi, XSS) en módulos de ataque.

### 1.2 Heurísticas de Phishing
Son reglas basadas en patrones estadísticos que los atacantes suelen usar para engañar a las víctimas.

*   **TLD de alto riesgo:** El "Top-Level Domain" es la extensión final (`.com`, `.net`). Extensiones como `.tk`, `.ml`, `.pw`, o `.xyz` suelen ser gratuitas o muy baratas, por lo que son abusadas masivamente por ciberdelincuentes.
*   **Acortadores de URL:** Servicios como `bit.ly` o `tinyurl.com`. Los atacantes los usan para ocultar el dominio malicioso final.
*   **Longitud de URL:** URLs inusualmente largas se usan a menudo para sobrepasar la capacidad de lectura del usuario en dispositivos móviles o para inyectar cargas útiles (payloads) masivas.
*   **Subdominios excesivos:** Un patrón clásico de phishing es crear múltiples subdominios gratuitos (`login.seguridad.banco.dominio-atacante.com`) para que parezca legítimo en la barra del navegador.
*   **Uso de guiones:** Muchos guiones en el dominio (ej. `secure-update-account-paypal.com`) intentan simular espacios o separar palabras clave para dar confianza.
*   **Palabras clave sospechosas:** Búsqueda en la URL de términos como `login`, `secure`, `verify`, `banking`, `account`, `update`. Si el dominio real no es reconocido como una entidad bancaria pero usa estas palabras, es casi seguro que es phishing.
*   **Descargas de ejecutables:** Detecta si la ruta termina en extensiones peligrosas (`.exe`, `.apk`, `.bat`, `.ps1`), advirtiendo sobre una posible distribución de malware.

### 1.3 Análisis de Marcas y Suplantación
*   **Typosquatting:** Consiste en registrar dominios con errores ortográficos muy comunes o parecidos al original. Ejemplo: `paypa1` (con el número 1), `g00gle` (con ceros), o `amazom` (con 'm').
*   **IDN/Homoglyphs:** Los ataques homográficos usan caracteres de alfabetos internacionales (como el cirílico) que visualmente son idénticos a los caracteres latinos. Un atacante puede registrar `apple.com` usando la letra cirílica "a" (U+0430), lo cual redirige a una web falsa, burlando al ojo humano.

### 1.4 Pruebas de Red (Network / DNS)
Son pruebas activas que interactúan con la infraestructura de Internet.

*   **Resolución DNS:** Se verifica si el dominio realmente tiene una dirección IP asignada. Si no resuelve, la URL está inactiva o el dominio fue dado de baja (posible "sinkhole").
*   **IPv4 / IPv6:** Conocer las direcciones del servidor para posteriores escaneos de puertos.
*   **Registro PTR (Reverse DNS):** Verifica a quién pertenece realmente la IP. Puede revelar si el sitio está alojado en una red residencial, un hosting de bajo costo, o infraestructura legítima.
*   **Detección de IPs Privadas/Internas:** Si el dominio resuelve a direcciones como `192.168.x.x`, `10.x.x.x` o `127.0.0.1`. Esto es una alerta CRÍTICA en un contexto de pentesting, ya que podría indicar un ataque de SSRF (Server-Side Request Forgery) o intentar atacar la red interna de quien ejecuta la herramienta.

### 1.5 Análisis HTTP y Aplicación Web
Se hace una petición a la URL y se examina la respuesta del servidor.

*   **Cadena de redirecciones:** Analiza si el servidor responde con códigos `301` o `302`. Los atacantes encadenan múltiples redirecciones a través de diferentes dominios hackeados para evadir filtros de seguridad antes de llegar al payload final.
*   **Revelación de tecnologías (Fingerprinting):** Lee cabeceras como `Server: Apache/2.4.41` o `X-Powered-By: PHP/5.6`. Esta "fuga de información" le dice al pentester exactamente qué software buscar vulnerabilidades (ej. un PHP obsoleto).
*   **Cabeceras de Seguridad Ausentes:**
    *   **HSTS (Strict-Transport-Security):** Obliga a usar siempre HTTPS. Si falta, el sitio es vulnerable a ataques de *Downgrade* o *Man-in-the-Middle*.
    *   **CSP (Content-Security-Policy):** Si falta, es más fácil que el sitio sea vulnerable a XSS (Cross-Site Scripting).
    *   **X-Frame-Options:** Si no está configurado adecuadamente, el sitio podría ser embebido en un iFrame en una web maliciosa (Clickjacking).
*   **Seguridad de Cookies:** Si la página emite cookies (especialmente de sesión), se verifica si tienen los flags `Secure` (solo viajan por HTTPS) y `HttpOnly` (no son accesibles mediante JavaScript, protegiendo contra XSS).

### 1.6 Análisis de Cifrado (TLS/SSL)
Comprueba el certificado digital para conexiones HTTPS.

*   **Validez y Caducidad:** Un certificado expirado o auto-firmado (Self-Signed) genera alertas en el navegador y puede significar infraestructura abandonada o interceptación activa.
*   **Emisor (Issuer):** Analiza quién firmó el certificado. Los certificados gratuitos (como Let's Encrypt) son excelentes, pero son los más usados en sitios de phishing (debido a su coste cero).
*   **SANs (Subject Alternative Names):** Revela otros dominios que están alojados en el mismo servidor web y comparten el certificado. Esto es vital en la fase de reconocimiento para descubrir la superficie de ataque oculta de una empresa.

### 1.7 Evaluación de Riesgo y Severidades
Todo el análisis genera una **Puntuación de Riesgo (Risk Score)** del 0 al 100 y le asigna un nivel de severidad general a la URL analizada.

*   `CRITICAL` (Crítico): Compromiso inminente o seguridad totalmente quebrantada (Ej. Phishing confirmado, credenciales en texto plano, IP privada maliciosa).
*   `HIGH` (Alto): Riesgos graves que facilitarían un ataque directo (Ej. HTTP sin cifrar, TLD malicioso).
*   `MEDIUM` (Medio): Malas prácticas de configuración (Ej. Fuga de versiones de software, cookies inseguras).
*   `LOW` (Bajo) / `INFO` (Informativo): Datos de contexto o ausencia de medidas de mitigación avanzadas.

---

## 2. Próximos Módulos (Roadmap)

### Port Scanning (Escáner de Puertos)
Identificará qué servicios están abiertos y escuchando en el servidor (ej. FTP en el puerto 21, SSH en el 22). Los puertos abiertos son puertas de entrada que requieren ser auditadas.

### Subdominios y Directorios
*   **Subdominios:** Descubrir áreas escondidas como `dev.ejemplo.com` o `admin.ejemplo.com`.
*   **Dir Busting (Fuerza Bruta de Rutas):** Buscar carpetas ocultas como `/backup/`, `/.git/` o `/api/v1/` que no están enlazadas públicamente pero contienen información sensible.

### Ataque (Offensive Module)
*   **DoS:** Pruebas de denegación de servicio para comprobar la resiliencia del servidor.
*   **Fuzzing:** Envío de datos inesperados a las entradas (URLs, formularios) para intentar provocar errores no controlados, volcados de memoria o inyecciones de código.

### Defensa (Defense Module)
Sugerencias de Hardening (endurecimiento): Se proveerá un reporte detallado con las acciones a tomar (ej. "Añadir cabecera CSP", "Actualizar Apache") para mitigar las vulnerabilidades encontradas.
