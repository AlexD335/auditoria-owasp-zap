# MiniFacturas — App de laboratorio (Auditoría con OWASP ZAP)

App web mínima, hecha a propósito con 6 vulnerabilidades, para el laboratorio
de **Seguridad en Aplicaciones Web** (Prof. Cristian Lopera Villa).

Sin dependencias externas: solo usa Node.js (`http`, `node:sqlite`, `crypto`).
No requiere `npm install`.

## Requisitos
- Node.js **v22.5 o superior** (usa el módulo nativo `node:sqlite`).

## Cómo correr

```bash
node server.js
```

Abre http://localhost:3000

Usuarios de prueba:
| usuario | contraseña      | rol   |
|---------|-----------------|-------|
| carlos  | carlos123       | user  |
| maria   | maria2024       | user  |
| admin   | S3cr3t0Admin!   | admin |

## Vulnerabilidades incluidas (rama `main`, commit "vulnerable")

| # | Vulnerabilidad | Dónde está | Cómo probarla rápido |
|---|---|---|---|
| 1 | JWT Broken Auth (`alg:none`) | `jwt-vulnerable.js`, `/login`, `/api/me` | Forjar un token con header `{"alg":"none"}` y firma vacía |
| 2 | SSRF | `POST /api/avatar` | Enviar `{"url":"http://localhost:3000/internal/secret"}` |
| 3 | CSRF | `POST /api/profile-form` | Abrir `csrf-poc.html` con sesión activa en otra pestaña |
| 4 | SQL Injection | `POST /login` | Usuario: `admin' --` |
| 5 | XSS reflejado | `GET /search?q=` | `q=<script>alert(1)</script>` |
| 6 | IDOR / Mass Assignment | `GET /api/invoices/:id`, `PUT /api/profile`, `POST /api/profile-form` | Cambiar el `:id` de la factura; o enviar `{"role":"admin"}` al perfil |

Ver `GUIA_ZAP.md` para el procedimiento paso a paso con OWASP ZAP sobre esta app.

**⚠️ No desplegar esta versión en una red pública ni en Internet.** Es para
correr en `localhost` / red local, solo con fines académicos.
