// jwt-vulnerable.js — Implementación MÍNIMA de JWT, A PROPÓSITO INSEGURA
// Vulnerabilidad: acepta alg:"none" (sin firma) y usa un secreto débil/hardcodeado para HS256.
// NO USAR EN PRODUCCIÓN. Solo para el laboratorio de OWASP ZAP.
'use strict';
const crypto = require('node:crypto');

const WEAK_SECRET = 'secret123'; // (!) secreto simétrico débil y hardcodeado

function base64url(input) {
  return Buffer.from(input).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function base64urlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return Buffer.from(str, 'base64').toString('utf8');
}

function sign(payload, { alg = 'HS256', expiresInSec = 3600 } = {}) {
  const header = { alg, typ: 'JWT' };
  const fullPayload = { ...payload, iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + expiresInSec };
  const h = base64url(JSON.stringify(header));
  const p = base64url(JSON.stringify(fullPayload));
  if (alg === 'none') {
    return `${h}.${p}.`;
  }
  const sig = crypto.createHmac('sha256', WEAK_SECRET).update(`${h}.${p}`).digest();
  const s = base64url(sig);
  return `${h}.${p}.${s}`;
}

// (!) VULNERABLE: confía en el campo "alg" que viene del propio token para decidir
// cómo validarlo, y si es "none" NO verifica ninguna firma.
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

  // (!) BUG: alg:none bypassa toda verificación de firma
  if (header.alg === 'none') {
    return payload;
  }

  // (!) BUG: no se valida que header.alg sea el algoritmo esperado por el servidor
  // (abre la puerta a confusión de algoritmos si en el futuro se agrega RS256)
  const expectedSig = base64url(
    crypto.createHmac('sha256', WEAK_SECRET).update(`${h}.${p}`).digest()
  );
  if (s !== expectedSig) return null;

  // (!) BUG: no se valida `exp` (expiración) ni `iss`
  return payload;
}

module.exports = { sign, verify };
