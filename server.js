// server.js — MiniFacturas (VERSIÓN VULNERABLE)
// App de laboratorio para auditoría con OWASP ZAP.
// Contiene 6 vulnerabilidades A PROPÓSITO:
//   1. JWT Broken Auth (alg:none)      -> ver jwt-vulnerable.js y /login, /api/me
//   2. SSRF                            -> POST /api/avatar
//   3. CSRF                            -> PUT /api/profile (sin token, sin SameSite)
//   4. SQL Injection                   -> POST /login
//   5. XSS reflejado                   -> GET /search
//   6. IDOR / Mass Assignment          -> GET /api/invoices/:id , PUT /api/profile
//
// NO DESPLEGAR EN INTERNET. Solo para red local / laboratorio académico.
'use strict';
const http = require('node:http');
const url = require('node:url');
const fs = require('node:fs');
const path = require('node:path');
const { db, init } = require('./db');
const jwtLib = require('./jwt-vulnerable');

const PORT = process.env.PORT || 3000;

init();

// ---------- Utilidades ----------
function sendHtml(res, status, html) {
  res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(html);
}
function sendJson(res, status, obj) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(obj));
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
function readBody(req) {
  return new Promise((resolve) => {
    let data = '';
    req.on('data', (chunk) => (data += chunk));
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

// (!) VULNERABLE: obtiene el usuario autenticado leyendo el JWT de la cookie,
// sin validar origen de la petición (sin token anti-CSRF, cookie sin SameSite).
function getAuthUser(req) {
  const cookies = parseCookies(req);
  const token = cookies.session || (req.headers.authorization || '').replace('Bearer ', '');
  if (!token) return null;
  return jwtLib.verify(token);
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
    // VULN 4: SQL INJECTION — login con concatenación directa
    // =========================================================
    if (req.method === 'POST' && pathname === '/login') {
      const { username, password } = await readFormBody(req);

      // (!) VULNERABLE: concatenación directa de entrada de usuario en SQL.
      // Probar: username = admin' --
      const sql = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
      console.log('[SQL ejecutado]', sql);

      let rows;
      try {
        rows = db.prepare(sql).all();
      } catch (e) {
        return sendHtml(res, 400, `<p>Error de consulta: ${e.message}</p>`);
      }

      if (rows.length === 0) {
        return sendHtml(res, 401, '<p>Credenciales inválidas. <a href="/">Volver</a></p>');
      }

      const user = rows[0];
      // =========================================================
      // VULN 1: JWT — firmado con secreto débil, verify() acepta alg:none
      // =========================================================
      const token = jwtLib.sign({ sub: user.id, username: user.username, role: user.role });

      // (!) VULNERABLE: cookie de sesión SIN HttpOnly, SIN Secure, SIN SameSite=Strict/Lax
      res.setHeader('Set-Cookie', `session=${token}; Path=/`);
      res.writeHead(302, { Location: '/perfil' });
      return res.end();
    }

    // =========================================================
    // VULN 1 (lectura): /api/me — confía en el JWT decodificado
    // =========================================================
    if (req.method === 'GET' && pathname === '/api/me') {
      const user = getAuthUser(req);
      if (!user) return sendJson(res, 401, { error: 'No autenticado' });
      return sendJson(res, 200, user);
    }

    // =========================================================
    // VULN 5: XSS REFLEJADO — /search?q= se renderiza sin escapar
    // =========================================================
    if (req.method === 'GET' && pathname === '/search') {
      const q = parsed.query.q || '';
      // (!) VULNERABLE: inserción directa de `q` en el HTML, sin encoding.
      const html = `
        <html><body>
          <h2>Resultados de búsqueda</h2>
          <p>Buscaste: ${q}</p>
          <p><a href="/">Volver</a></p>
        </body></html>`;
      return sendHtml(res, 200, html);
    }

    // =========================================================
    // VULN 2: SSRF — el backend hace fetch de una URL dada por el usuario
    // =========================================================
    if (req.method === 'POST' && pathname === '/api/avatar') {
      const body = await readJsonBody(req);
      const targetUrl = body.url;
      if (!targetUrl) return sendJson(res, 400, { error: 'Falta url' });

      // (!) VULNERABLE: sin allowlist de dominios/IPs, sin bloqueo de rangos privados,
      // sin restricción de esquema (permitiría file://, etc. según el parser usado).
      console.log('[SSRF] El servidor va a solicitar:', targetUrl);
      const lib = targetUrl.startsWith('https') ? require('node:https') : require('node:http');
      lib
        .get(targetUrl, (proxyRes) => {
          let data = '';
          proxyRes.on('data', (c) => (data += c));
          proxyRes.on('end', () => sendJson(res, 200, { fetchedFrom: targetUrl, body: data.slice(0, 2000) }));
        })
        .on('error', (e) => sendJson(res, 502, { error: 'No se pudo obtener la URL', detail: e.message }));
      return;
    }

    // Endpoint interno NO enlazado desde la UI — simula un servicio interno / metadata
    // que solo debería ser alcanzable desde dentro de la red, y que el SSRF expone.
    if (req.method === 'GET' && pathname === '/internal/secret') {
      return sendJson(res, 200, {
        warning: 'Este endpoint interno no debería ser accesible desde fuera del servidor.',
        internal_api_key: 'FLAG{SSRF-interno-expuesto-20251109}',
      });
    }

    // =========================================================
    // VULN 6: IDOR — cualquier usuario autenticado puede leer cualquier factura
    // =========================================================
    if (req.method === 'GET' && pathname.startsWith('/api/invoices/')) {
      const user = getAuthUser(req);
      if (!user) return sendJson(res, 401, { error: 'No autenticado' });

      const id = pathname.split('/').pop();
      // (!) VULNERABLE: no se valida que la factura pertenezca a user.sub (owner_id)
      const invoice = db.prepare('SELECT * FROM invoices WHERE id = ?').get(id);
      if (!invoice) return sendJson(res, 404, { error: 'No encontrada' });
      return sendJson(res, 200, invoice);
    }

    // =========================================================
    // VULN 3 + 6: CSRF + Mass Assignment — actualizar perfil
    // =========================================================
    if (req.method === 'PUT' && pathname === '/api/profile') {
      const user = getAuthUser(req);
      if (!user) return sendJson(res, 401, { error: 'No autenticado' });

      const body = await readJsonBody(req);

      // (!) VULNERABLE (Mass Assignment): se vuelcan TODOS los campos del body
      // directamente a la actualización, incluido "role" si el atacante lo envía.
      const fields = Object.keys(body);
      const setClause = fields.map((f) => `${f} = ?`).join(', ');
      const values = fields.map((f) => body[f]);

      if (fields.length > 0) {
        // (!) No hay verificación de token anti-CSRF ni de cabecera Origin/Referer:
        // esta petición podría dispararse desde un formulario en otro dominio
        // aprovechando que la cookie de sesión se envía automáticamente.
        const sql = `UPDATE users SET ${setClause} WHERE id = ?`;
        db.prepare(sql).run(...values, user.sub);
      }

      const updated = db.prepare('SELECT id, username, role, email FROM users WHERE id = ?').get(user.sub);
      return sendJson(res, 200, updated);
    }

    // =========================================================
    // VULN 3: CSRF (PoC con formulario clásico) — misma falla que /api/profile
    // pero accesible con un <form method="POST"> simple (sin preflight CORS),
    // tal como la explotaría un sitio atacante externo.
    // =========================================================
    if (req.method === 'POST' && pathname === '/api/profile-form') {
      const user = getAuthUser(req);
      if (!user) return sendJson(res, 401, { error: 'No autenticado' });

      const body = await readFormBody(req);
      // (!) VULNERABLE: sin token anti-CSRF, sin revisar Origin/Referer,
      // y de nuevo sin allowlist de campos (mass assignment vía formulario).
      const fields = Object.keys(body);
      if (fields.length > 0) {
        const setClause = fields.map((f) => `${f} = ?`).join(', ');
        const values = fields.map((f) => body[f]);
        db.prepare(`UPDATE users SET ${setClause} WHERE id = ?`).run(...values, user.sub);
      }
      return sendHtml(res, 200, '<p>Perfil actualizado.</p>');
    }

    // 404
    return sendHtml(res, 404, '<h1>404</h1>');
  } catch (err) {
    console.error(err);
    return sendJson(res, 500, { error: 'Error interno', detail: err.message });
  }
});

server.listen(PORT, () => {
  console.log(`\n[MiniFacturas - VULNERABLE] escuchando en http://localhost:${PORT}`);
  console.log('Usuarios de prueba: carlos/carlos123 , maria/maria2024 , admin/S3cr3t0Admin!\n');
});
