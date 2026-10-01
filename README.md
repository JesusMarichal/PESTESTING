# PESTesting Suite

Suite de ciberseguridad para **análisis, ataque y defensa**, construida en Python puro
(sin dependencias externas). Diseñada para crecer módulo a módulo.

> Uso legal: emplear únicamente contra sistemas de tu propiedad o con autorización expresa.

## Estado del proyecto

| Módulo | Estado | Descripción |
|---|---|---|
| `url` (recon) | ✅ listo | Análisis profundo de URLs: estructura, phishing, DNS, HTTP, TLS |
| `scan` (recon) | ✅ listo | Escáner de puertos TCP multihilo: banner grabbing, servicios de riesgo |
| Port scanning | ✅ listo | Ver módulo `scan` |
| Subdominios | ⏳ roadmap | Enumeración de subdominios |
| Directorios | ⏳ roadmap | Fuerza bruta de rutas (dir busting) |
| Ataques | ⏳ roadmap | Módulo ofensivo (DoS, fuzzing, explotación básica) |
| Defensa | ⏳ roadmap | Hardening, detección de intrusiones, monitoreo |

## Instalación

```bash
# Solo requiere Python 3.8 o superior
python main.py --version
# v0.1.1
```

## Uso

```bash
# Análisis completo de una URL (DNS + HTTP + TLS)
python main.py url https://ejemplo.com

# Análisis sin comprobaciones de red (heurísticas estáticas)
python main.py url http://paypa1-secure.tk/login --offline

# Opciones
python main.py url <url> --timeout 5        # timeout de red (s)
python main.py url <url> --format json       # informe solo en JSON (o html / both)
python main.py url <url> --no-save           # no guardar informes
python main.py url <url> --no-color          # salida sin colores

# ---- Escáner de puertos TCP ----
python main.py scan ejemplo.com                         # puertos comunes (~130)
python main.py scan 192.168.1.1 --ports 1-1024          # rango personalizado
python main.py scan ejemplo.com --ports 22,80,443,8080  # lista específica
python main.py scan ejemplo.com --ports all             # todos los puertos (1-65535)
python main.py scan ejemplo.com --threads 200 --timeout 0.8   # ajuste de velocidad
python main.py scan ejemplo.com --no-banner             # sin banner grabbing
```

### Qué analiza el módulo `url`

- **Estructura**: esquema, host, puerto, ruta, query, fragmento, credenciales embebidas
- **Heurísticas de phishing**: TLD de alto riesgo, acortadores, longitud, subdominios,
  guiones, palabras clave sospechosas, descargas de ejecutables
- **Marcas**: detección de typosquatting (`paypa1`, `g00gle`), domain squatting e IDN/homoglyphs
- **Red**: resolución DNS, IPv4/IPv6, registro PTR, IPs privadas
- **HTTP**: cadena de redirecciones, cabeceras de seguridad ausentes (HSTS, CSP...),
  revelación de tecnologías, cookies sin `Secure`/`HttpOnly`
- **TLS**: validez del certificado, caducidad, emisor, protocolo obsoleto, SANs
- **Riesgo**: puntuación 0-100 y nivel (BAJO / MEDIO / ALTO / CRITICO)

Los informes se guardan en `reports/` en formato JSON y HTML.

## Estructura del proyecto

```
PESTESTING/
├── main.py                  # CLI principal (punto de entrada)
├── config/
│   └── settings.json        # listas y umbrales configurables
├── core/
│   ├── colors.py            # colores ANSI (soporte Windows)
│   ├── config.py            # carga de configuración
│   └── reporter.py          # informes: consola, JSON, HTML
├── modules/
│   └── recon/
│       └── url_analyzer.py  # motor de análisis de URLs
├── reports/                 # informes generados
└── requirements.txt
```

## Convenciones

- Cada módulo nuevo vive en `modules/<categoría>/` (`recon`, `attack`, `defense`).
- Los hallazgos usan severidades: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`, `OK`.
- La configuración compartida (listas, umbrales) va en `config/settings.json`.
