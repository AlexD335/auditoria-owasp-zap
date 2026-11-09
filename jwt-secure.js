// jwt-secure.js — PARCHE de la vulnerabilidad #1 (JWT Broken Authentication)
//
// Cambios respecto a jwt-vulnerable.js:
//  1. Se RECHAZA explícitamente alg:"none" y cualquier alg distinto al
//     esperado por el servidor (HS256 fijo, no se lee del token entrante).
//  2. El secreto ya no está hardcodeado en el código: se toma de la
//     variable de entorno JWT_SECRET, con una advertencia si no se definió.
//  3. Se valida `exp` (expiración) e `iss` (emisor) del payload.
//  4. Comparación de firma con crypto.timingSafeEqual (evita timing attacks).
'use strict';
const crypto = require('node:crypto');

const ISSUER = 'minifacturas-app';
const EXPECTED_ALG = 'HS256';

const SECRET = process.env.JWT_SECRET;
if (!SECRET) {
  // En un entorno real esto debería detener el arranque del servidor.
  console.warn(
    '[jwt-secure] ADVERTENCIA: JWT_SECRET no está definido. ' +
      'Usando un secreto aleatorio de sesión (los tokens no sobrevivirán un reinicio). ' +
      'Define JWT_SECRET en tu .env para producción.'
  );
}
const EFFECTIVE_SECRET = SECRET || crypto.randomBytes(32).toString('hex');

function base64url(input) {
  return Buffer.from(input).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function base64urlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return Buffer.from(str, 'base64').toString('utf8');
}

function sign(payload, { expiresInSec = 3600 } = {}) {
  const header = { alg: EXPECTED_ALG, typ: 'JWT' };
  const fullPayload = {
    ...payload,
    iss: ISSUER,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + expiresInSec,
  };
  const h = base64url(JSON.stringify(header));
  const p = base64url(JSON.stringify(fullPayload));
  const sig = crypto.createHmac('sha256', EFFECTIVE_SECRET).update(`${h}.${p}`).digest();
  return `${h}.${p}.${base64url(sig)}`;
}

function verify(token) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [h, p, s] = parts;

  let header, payload;
  try {
    header = JSON.parse(base64urlDecode(h));
    payload = JSON.parse(base64urlDecode(p));
  } catch {
    return null;
  }

  // PARCHE: el algoritmo esperado lo decide el SERVIDOR, no el token.
  // Se rechaza alg:"none" y cualquier otro algoritmo no soportado.
  if (header.alg !== EXPECTED_ALG) {
    return null;
  }

  const expectedSig = crypto.createHmac('sha256', EFFECTIVE_SECRET).update(`${h}.${p}`).digest();
  let providedSig;
  try {
    providedSig = Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
  } catch {
    return null;
  }
  if (providedSig.length !== expectedSig.length || !crypto.timingSafeEqual(providedSig, expectedSig)) {
    return null;
  }

  // PARCHE: validar expiración y emisor.
  const now = Math.floor(Date.now() / 1000);
  if (typeof payload.exp !== 'number' || payload.exp < now) return null;
  if (payload.iss !== ISSUER) return null;

  return payload;
}

module.exports = { sign, verify };
