// server.js — MiniFacturas (VERSIÓN PARCHEADA)
// App de laboratorio para auditoría con OWASP ZAP.
// Contiene la remediación de las 6 vulnerabilidades detectadas en la Fase 2:
//   1. JWT Broken Auth   -> jwt-secure.js rechaza alg:none, valida firma/exp/iss
//   2. SSRF               -> POST /api/avatar valida contra una allowlist
//   3. CSRF                -> token anti-CSRF (Synchronizer Token Pattern) + SameSite
//   4. SQL Injection      -> POST /login usa consultas parametrizadas (prepared statements)
//   5. XSS reflejado      -> GET /search aplica HTML output encoding
//   6. IDOR / Mass Assign -> valida dueño del recurso + allowlist de campos editables (DTO)
//
// Ver GUIA_ZAP.md para el procedimiento de re-escaneo de verificación.
'use strict';
const http = require('node:http');
const url = require('node:url');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const dns = require('node:dns').promises;
const net = require('node:net');
const { db, init, verifyPassword } = require('./db');
const jwtLib = require('./jwt-secure');

const PORT = process.env.PORT || 3000;

init();

// ---------- Utilidades ----------
function sendHtml(res, status, html, extraHeaders = {}) {
  res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8', ...extraHeaders });
  res.end(html);
}
function sendJson(res, status, obj, extraHeaders = {}) {
  res.writeHead(status, { 'Content-Type': 'application/json', ...extraHeaders });
  res.end(JSON.stringify(obj));
}

// PARCHE (vuln 5 - XSS): escapado de HTML antes de insertar cualquier dato
// controlado por el usuario en una respuesta HTML.
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function parseCookies(req) {
  const header = req.headers.cookie || '';
  const out = {};
  header.split(';').forEach((pair) => {
    const idx = pair.indexOf('=');
    if (idx > -1) out[pair.slice(0, idx).trim()] = decodeURIComponent(pair.slice(idx + 1).trim());
  });
  return out;
}
function readBody(req, maxBytes = 1_000_000) {
  return new Promise((resolve, reject) => {
    let data = '';
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > maxBytes) {
        reject(new Error('Body demasiado grande'));
        req.destroy();
        return;
      }
      data += chunk;
    });
    req.on('end', () => resolve(data));
  });
}
async function readJsonBody(req) {
  const raw = await readBody(req);
  try {
    return JSON.parse(raw || '{}');
  } catch {
    return {};
  }
}
async function readFormBody(req) {
  const raw = await readBody(req);
  const out = {};
  new url.URLSearchParams(raw).forEach((v, k) => (out[k] = v));
  return out;
}

// Obtiene el usuario autenticado a partir del JWT (ya validado estrictamente
// por jwt-secure.js: rechaza alg:none, valida firma/exp/iss).
function getAuthUser(req) {
  const cookies = parseCookies(req);
  const token = cookies.session || (req.headers.authorization || '').replace('Bearer ', '');
  if (!token) return null;
  return jwtLib.verify(token);
}

// =========================================================
// PARCHE (vuln 3 - CSRF): Synchronizer Token Pattern.
// Se guarda un mapa csrfToken -> username en memoria (alcanza para el
// laboratorio; en producción iría ligado a la sesión en el store de sesiones).
// El token se expone en una cookie NO-HttpOnly (csrf_token) para que el
// frontend JS pueda leerlo y mandarlo de vuelta en una cabecera, siguiendo
// el patrón "doble envío" combinado con verificación server-side.
// =========================================================
const csrfTokens = new Map(); // token -> userId

function issueCsrfToken(userId) {
  const token = crypto.randomBytes(24).toString('hex');
  csrfTokens.set(token, userId);
  return token;
}
function checkCsrfToken(req, userId) {
  const headerToken = req.headers['x-csrf-token'];
  const owner = headerToken && csrfTokens.get(headerToken);
  return owner !== undefined && owner === userId;
}

// =========================================================
// PARCHE (vuln 2 - SSRF): allowlist de hosts + bloqueo de rangos privados
// y de esquemas distintos a http/https.
// =========================================================
const SSRF_ALLOWED_HOSTS = new Set(['example.com', 'picsum.photos', 'httpbin.org']);

function isPrivateOrReservedIp(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    if (a === 127) return true; // loopback
    if (a === 10) return true; // 10.0.0.0/8
    if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
    if (a === 192 && b === 168) return true; // 192.168.0.0/16
    if (a === 169 && b === 254) return true; // link-local / metadata (169.254.169.254)
    if (a === 0) return true;
    return false;
  }
  if (ip === '::1') return true; // loopback IPv6
  return false;
}

async function assertSafeSsrfTarget(targetUrl) {
  let parsedUrl;
  try {
    parsedUrl = new url.URL(targetUrl);
  } catch {
    throw new Error('URL inválida');
  }
  // Solo esquemas http/https (bloquea file://, gopher://, etc.)
  if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
    throw new Error(`Esquema no permitido: ${parsedUrl.protocol}`);
  }
  // Allowlist de dominios explícitamente autorizados
  if (!SSRF_ALLOWED_HOSTS.has(parsedUrl.hostname)) {
    throw new Error(`Host no autorizado: ${parsedUrl.hostname}. Hosts permitidos: ${[...SSRF_ALLOWED_HOSTS].join(', ')}`);
  }
  // Resolver DNS y bloquear si apunta a rangos privados/reservados/loopback
  // (evita DNS rebinding hacia 127.0.0.1 o metadata 169.254.169.254)
  const { address } = await dns.lookup(parsedUrl.hostname);
  if (isPrivateOrReservedIp(address)) {
    throw new Error(`El host resuelve a una IP privada/reservada no permitida: ${address}`);
  }
  return parsedUrl;
}

const PUBLIC_DIR = path.join(__dirname, 'public');

// ---------- Servidor ----------
const server = http.createServer(async (req, res) => {
  const parsed = url.parse(req.url, true);
  const pathname = parsed.pathname;

  try {
    // ---- Archivos estáticos simples ----
    if (req.method === 'GET' && pathname === '/') {
      return sendHtml(res, 200, fs.readFileSync(path.join(PUBLIC_DIR, 'index.html'), 'utf8'));
    }
    if (req.method === 'GET' && pathname === '/perfil') {
      return sendHtml(res, 200, fs.readFileSync(path.join(PUBLIC_DIR, 'perfil.html'), 'utf8'));
    }
    if (req.method === 'GET' && pathname === '/facturas') {
      return sendHtml(res, 200, fs.readFileSync(path.join(PUBLIC_DIR, 'facturas.html'), 'utf8'));
    }

    // =========================================================
    // PARCHE vuln 4: SQL INJECTION — consulta parametrizada (prepared statement)
    // =========================================================
    if (req.method === 'POST' && pathname === '/login') {
      const { username, password } = await readFormBody(req);
      if (!username || !password) {
        return sendHtml(res, 400, '<p>Usuario y contraseña son obligatorios.</p>');
      }

      // PARCHE: los valores de usuario viajan como parámetros (?), nunca
      // concatenados al texto del SQL. SQLite los trata siempre como datos.
      const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);

      // PARCHE (bonus): comparación de contraseña hasheada con scrypt,
      // en tiempo constante (ver verifyPassword en db.js).
      if (!user || !verifyPassword(password, user.password)) {
        return sendHtml(res, 401, '<p>Credenciales inválidas. <a href="/">Volver</a></p>');
      }

      // PARCHE vuln 1: jwt-secure.js firma con secreto de entorno, fuerza
      // alg HS256, agrega iss/exp y los valida siempre en verify().
      const token = jwtLib.sign({ sub: user.id, username: user.username, role: user.role });
      const csrfToken = issueCsrfToken(user.id);

      // PARCHE vuln 3 (parte 1): cookie de sesión con HttpOnly + SameSite=Lax.
      // (Secure se omite aquí porque el laboratorio corre en http://localhost;
      // en producción con HTTPS siempre debe incluirse `Secure`.)
      res.setHeader('Set-Cookie', [
        `session=${token}; Path=/; HttpOnly; SameSite=Lax`,
        `csrf_token=${csrfToken}; Path=/; SameSite=Lax`, // legible por JS a propósito (doble envío)
      ]);
      res.writeHead(302, { Location: '/perfil' });
      return res.end();
    }

    if (req.method === 'GET' && pathname === '/api/me') {
      const user = getAuthUser(req);
      if (!user) return sendJson(res, 401, { error: 'No autenticado' });
      return sendJson(res, 200, user);
    }

    // =========================================================
    // PARCHE vuln 5: XSS — output encoding antes de insertar en el HTML
    // =========================================================
    if (req.method === 'GET' && pathname === '/search') {
      const q = parsed.query.q || '';
      // PARCHE: se escapa `q` con escapeHtml() antes de insertarlo.
      // Además se añade un header Content-Security-Policy como defensa en profundidad.
      const html = `
        <html><body>
          <h2>Resultados de búsqueda</h2>
          <p>Buscaste: ${escapeHtml(q)}</p>
          <p><a href="/">Volver</a></p>
        </body></html>`;
      return sendHtml(res, 200, html, {
        'Content-Security-Policy': "default-src 'self'; script-src 'self'",
      });
    }

    // =========================================================
    // PARCHE vuln 2: SSRF — allowlist + bloqueo de IPs privadas/reservadas
    // =========================================================
    if (req.method === 'POST' && pathname === '/api/avatar') {
      const body = await readJsonBody(req);
      const targetUrl = body.url;
      if (!targetUrl) return sendJson(res, 400, { error: 'Falta url' });

      let safeUrl;
      try {
        safeUrl = await assertSafeSsrfTarget(targetUrl);
      } catch (e) {
        return sendJson(res, 400, { error: 'Solicitud rechazada', detail: e.message });
      }

      const lib = safeUrl.protocol === 'https:' ? require('node:https') : require('node:http');
      lib
        .get(safeUrl.toString(), (proxyRes) => {
          let data = '';
          proxyRes.on('data', (c) => (data += c));
          proxyRes.on('end', () => sendJson(res, 200, { fetchedFrom: safeUrl.toString(), body: data.slice(0, 2000) }));
        })
        .on('error', (e) => sendJson(res, 502, { error: 'No se pudo obtener la URL', detail: e.message }));
      return;
    }

    // El endpoint interno sigue existiendo para que el re-escaneo demuestre
    // que YA NO es alcanzable a través de /api/avatar (sí sigue existiendo
    // en el servidor porque en un caso real sería un servicio interno aparte,
    // no expuesto en la misma red que este backend).
    if (req.method === 'GET' && pathname === '/internal/secret') {
      return sendJson(res, 200, {
        warning: 'Este endpoint interno no debería ser accesible desde fuera del servidor.',
        internal_api_key: 'FLAG{SSRF-interno-expuesto-20251109}',
      });
    }

    // =========================================================
    // PARCHE vuln 6: IDOR — se valida que la factura pertenezca al usuario autenticado
    // =========================================================
    if (req.method === 'GET' && pathname.startsWith('/api/invoices/')) {
      const user = getAuthUser(req);
      if (!user) return sendJson(res, 401, { error: 'No autenticado' });

      const id = pathname.split('/').pop();
      const invoice = db.prepare('SELECT * FROM invoices WHERE id = ?').get(id);

      // PARCHE: control de acceso a nivel de objeto (BOLA/IDOR fix).
      // Los administradores sí pueden ver cualquier factura; un usuario normal
      // solo las propias.
      if (!invoice) return sendJson(res, 404, { error: 'No encontrada' });
      if (invoice.owner_id !== user.sub && user.role !== 'admin') {
        return sendJson(res, 403, { error: 'No tienes permiso para ver esta factura' });
      }
      return sendJson(res, 200, invoice);
    }

    // =========================================================
    // PARCHE vuln 3 + 6: CSRF token + Mass Assignment (DTO allowlist)
    // =========================================================
    if (req.method === 'PUT' && pathname === '/api/profile') {
      const user = getAuthUser(req);
      if (!user) return sendJson(res, 401, { error: 'No autenticado' });

      // PARCHE vuln 3: exige el token anti-CSRF enviado en header X-CSRF-Token,
      // que debe coincidir con el emitido en el login para ESTE usuario.
      if (!checkCsrfToken(req, user.sub)) {
        return sendJson(res, 403, { error: 'Token CSRF inválido o ausente' });
      }

      const body = await readJsonBody(req);

      // PARCHE vuln 6 (Mass Assignment): DTO allowlisting — solo se aceptan
      // los campos explícitamente permitidos. "role" NUNCA se acepta aquí.
      const ALLOWED_PROFILE_FIELDS = ['email'];
      const fields = Object.keys(body).filter((f) => ALLOWED_PROFILE_FIELDS.includes(f));

      if (fields.length > 0) {
        const setClause = fields.map((f) => `${f} = ?`).join(', ');
        const values = fields.map((f) => body[f]);
        db.prepare(`UPDATE users SET ${setClause} WHERE id = ?`).run(...values, user.sub);
      }

      const updated = db.prepare('SELECT id, username, role, email FROM users WHERE id = ?').get(user.sub);
      return sendJson(res, 200, updated);
    }

    // =========================================================
    // Endpoint de formulario clásico: ahora exige igualmente el token CSRF
    // (se envía como campo oculto, patrón Synchronizer Token clásico) y
    // aplica la misma allowlist de campos.
    // =========================================================
    if (req.method === 'POST' && pathname === '/api/profile-form') {
      const user = getAuthUser(req);
      if (!user) return sendJson(res, 401, { error: 'No autenticado' });

      const body = await readFormBody(req);

      // PARCHE vuln 3: token anti-CSRF como campo oculto del formulario.
      if (!checkCsrfToken({ headers: { 'x-csrf-token': body.csrf_token } }, user.sub)) {
        return sendJson(res, 403, { error: 'Token CSRF inválido o ausente' });
      }

      // PARCHE vuln 6: misma allowlist que /api/profile.
      const ALLOWED_PROFILE_FIELDS = ['email'];
      const fields = Object.keys(body).filter((f) => ALLOWED_PROFILE_FIELDS.includes(f));
      if (fields.length > 0) {
        const setClause = fields.map((f) => `${f} = ?`).join(', ');
        const values = fields.map((f) => body[f]);
        db.prepare(`UPDATE users SET ${setClause} WHERE id = ?`).run(...values, user.sub);
      }
      return sendHtml(res, 200, '<p>Perfil actualizado.</p>');
    }

    // Entrega el token CSRF vigente del usuario autenticado, para que el
    // frontend (o el propio ZAP en el re-escaneo) pueda incluirlo en sus pruebas.
    if (req.method === 'GET' && pathname === '/api/csrf-token') {
      const user = getAuthUser(req);
      if (!user) return sendJson(res, 401, { error: 'No autenticado' });
      const cookies = parseCookies(req);
      return sendJson(res, 200, { csrfToken: cookies.csrf_token || null });
    }

    // 404
    return sendHtml(res, 404, '<h1>404</h1>');
  } catch (err) {
    console.error(err);
    return sendJson(res, 500, { error: 'Error interno', detail: err.message });
  }
});

server.listen(PORT, () => {
  console.log(`\n[MiniFacturas - PARCHEADO] escuchando en http://localhost:${PORT}`);
  console.log('Usuarios de prueba: carlos/carlos123 , maria/maria2024 , admin/S3cr3t0Admin!\n');
  if (!process.env.JWT_SECRET) {
    console.log('Tip: exporta JWT_SECRET="algo-largo-y-aleatorio" antes de arrancar en un entorno real.\n');
  }
});
