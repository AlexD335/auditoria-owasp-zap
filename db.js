// db.js — Inicializa la base de datos SQLite para MiniFacturas
// Usa el módulo nativo node:sqlite (experimental en Node 22+, no requiere npm install)
'use strict';
const { DatabaseSync } = require('node:sqlite');
const path = require('node:path');

const DB_PATH = path.join(__dirname, 'minifacturas.db');
const db = new DatabaseSync(DB_PATH);

function init() {
  db.exec(`PRAGMA foreign_keys = OFF;`);
  db.exec(`
    DROP TABLE IF EXISTS invoices;
    DROP TABLE IF EXISTS users;

    CREATE TABLE users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      email TEXT
    );

    CREATE TABLE invoices (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      owner_id INTEGER NOT NULL,
      concept TEXT NOT NULL,
      amount REAL NOT NULL,
      FOREIGN KEY (owner_id) REFERENCES users(id)
    );
  `);

  const insertUser = db.prepare(
    'INSERT INTO users (username, password, role, email) VALUES (?, ?, ?, ?)'
  );
  insertUser.run('carlos', 'carlos123', 'user', 'carlos@test.com');
  insertUser.run('admin', 'S3cr3t0Admin!', 'admin', 'admin@minifacturas.local');
  insertUser.run('maria', 'maria2024', 'user', 'maria@test.com');

  const insertInvoice = db.prepare(
    'INSERT INTO invoices (owner_id, concept, amount) VALUES (?, ?, ?)'
  );
  insertInvoice.run(1, 'Consultoría noviembre', 1200000);
  insertInvoice.run(1, 'Licencia software', 350000);
  insertInvoice.run(3, 'Servicio de diseño', 800000);
  insertInvoice.run(2, 'Factura confidencial admin', 9999999);

  console.log('[db] Base de datos inicializada con datos de prueba en', DB_PATH);
}

module.exports = { db, init, DB_PATH };
