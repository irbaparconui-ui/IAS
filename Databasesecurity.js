
'use strict';

const path   = require('path');
const crypto = require('crypto');
const env    = require('./environment');
const { DatabaseError, logger } = require('./errorHandler');

// ── SQLite3 (zero-dependency DB for portability) ─────────────
//    In production swap for pg/mysql2 — the API surface is identical
let _db = null;

function getDb() {
  if (_db) return _db;

  try {
    const Database = require('better-sqlite3');
    const dbFile   = env.str('DB_NAME', 'secure_app.db');
    _db = new Database(path.resolve(dbFile), {
      verbose: env.isDebug() ? (sql) => logger.debug('SQL', { sql }) : null,
    });

    // Harden SQLite session
    _db.pragma('journal_mode = WAL');
    _db.pragma('foreign_keys = ON');
    _db.pragma('secure_delete = ON');

    logger.info('Database connection established', {
      engine: 'sqlite',
      file:   dbFile,
    });
    return _db;
  } catch (err) {
    logger.error('Database connection failed', {}, err);
    throw new DatabaseError('Database connection failed. Check DB_NAME in .env.');
  }
}

// ============================================================
// WHITELIST — prevents schema enumeration attacks
// ============================================================

const ALLOWED_TABLES  = new Set(['users', 'products', 'audit_log', 'sessions']);
const SENSITIVE_COLS  = new Set(['password_hash', 'password', 'token', 'secret', 'api_key', 'ssn']);

const ALLOWED_ORDER_COLS = {
  users:    new Set(['id', 'username', 'email', 'created_at']),
  products: new Set(['id', 'name', 'price', 'created_at']),
};

function assertTable(table) {
  if (!ALLOWED_TABLES.has(table))
    throw new DatabaseError(`Table '${table}' is not permitted.`, { table });
}

function assertOrderCol(table, col) {
  const allowed = ALLOWED_ORDER_COLS[table];
  if (!allowed || !allowed.has(col))
    throw new DatabaseError(`Order column '${col}' is not permitted for '${table}'.`);
}

// ============================================================
// RESULT MASKING — sensitive columns → [REDACTED]
// ============================================================

function maskRow(row) {
  if (!row || typeof row !== 'object') return row;
  const out = {};
  for (const [k, v] of Object.entries(row)) {
    out[k] = SENSITIVE_COLS.has(k) ? '[REDACTED]' : v;
  }
  return out;
}

function maskRows(rows) {
  return Array.isArray(rows) ? rows.map(maskRow) : rows;
}

// ============================================================
// QUERY HELPERS  (parameterized — no interpolation)
// ============================================================

const MAX_ROWS = 1000;

function queryAll(sql, params = [], limit = 100) {
  if (limit > MAX_ROWS) throw new DatabaseError(`Result limit cannot exceed ${MAX_ROWS} rows.`);
  _assertSafeSql(sql);

  try {
    const db   = getDb();
    const rows = db.prepare(sql).all(...params);
    return maskRows(rows.slice(0, limit));
  } catch (err) {
    _handleDbError(err, sql, params);
  }
}

function queryOne(sql, params = []) {
  _assertSafeSql(sql);
  try {
    const db  = getDb();
    const row = db.prepare(sql).get(...params);
    return row ? maskRow(row) : null;
  } catch (err) {
    _handleDbError(err, sql, params);
  }
}

function execute(sql, params = []) {
  _assertSafeSql(sql);
  try {
    const db     = getDb();
    const result = db.prepare(sql).run(...params);
    return result.changes;
  } catch (err) {
    _handleDbError(err, sql, params);
  }
}

// ── Safe dynamic INSERT (no string interpolation) ────────────
function insertRow(table, data) {
  assertTable(table);

  const cols        = Object.keys(data);
  const placeholders = cols.map(() => '?').join(', ');
  const colList     = cols.map(c => `"${c}"`).join(', ');
  const sql         = `INSERT INTO "${table}" (${colList}) VALUES (${placeholders})`;

  try {
    const db     = getDb();
    const result = db.prepare(sql).run(...Object.values(data));
    return result.lastInsertRowid;
  } catch (err) {
    // Log column names only — never values (may contain passwords)
    _handleDbError(err, sql, cols);
  }
}

// ── Safe dynamic UPDATE ───────────────────────────────────────
function updateRows(table, data, where) {
  assertTable(table);

  const setClauses   = Object.keys(data).map(k  => `"${k}" = ?`).join(', ');
  const whereClauses = Object.keys(where).map(k => `"${k}" = ?`).join(' AND ');
  const sql          = `UPDATE "${table}" SET ${setClauses} WHERE ${whereClauses}`;
  const params       = [...Object.values(data), ...Object.values(where)];

  try {
    const db     = getDb();
    const result = db.prepare(sql).run(...params);
    return result.changes;
  } catch (err) {
    _handleDbError(err, sql, Object.keys({ ...data, ...where }));
  }
}

// ============================================================
// TRANSACTION WRAPPER (auto-rollback on error)
// ============================================================

function withTransaction(fn) {
  const db = getDb();
  const tx = db.transaction(fn);
  try {
    return tx();
  } catch (err) {
    logger.error('Transaction rolled back', { reason: err.message });
    if (err instanceof DatabaseError) throw err;
    throw new DatabaseError('Transaction failed. Changes rolled back.');
  }
}

// ============================================================
// AUDIT LOG — immutable, append-only
// ============================================================

function auditLog({ action, userId = null, entity = null, entityId = null, ip = '', meta = null }) {
  try {
    const db = getDb();
    db.prepare(`
      INSERT INTO audit_log (action, user_id, entity, entity_id, ip_address, meta, created_at)
      VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
    `).run(
      action,
      userId,
      entity,
      entityId ? String(entityId) : null,
      ip,
      meta ? JSON.stringify(_scrubMeta(meta)) : null,
    );
  } catch (err) {
    // Audit failures must not crash the main flow — log but continue
    logger.error('Audit log write failed', { action }, err);
  }
}

function _scrubMeta(obj) {
  if (!obj) return obj;
  const out = {};
  for (const [k, v] of Object.entries(obj)) {
    out[k] = SENSITIVE_COLS.has(k) ? '[REDACTED]' : v;
  }
  return out;
}

// ============================================================
// SCHEMA INITIALIZATION
// ============================================================

function initSchema() {
  const db = getDb();
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      username      TEXT    NOT NULL UNIQUE,
      email         TEXT    NOT NULL UNIQUE,
      password_hash TEXT    NOT NULL,
      is_active     INTEGER NOT NULL DEFAULT 1,
      created_at    TEXT    NOT NULL DEFAULT (datetime('now')),
      updated_at    TEXT    NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS products (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      name        TEXT    NOT NULL,
      description TEXT    DEFAULT '',
      price       REAL    NOT NULL,
      stock       INTEGER NOT NULL DEFAULT 0,
      created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS audit_log (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id     INTEGER,
      action      TEXT    NOT NULL,
      entity      TEXT,
      entity_id   TEXT,
      ip_address  TEXT    NOT NULL DEFAULT '',
      meta        TEXT,
      created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS sessions (
      id          TEXT    PRIMARY KEY,
      user_id     INTEGER NOT NULL,
      expires_at  TEXT    NOT NULL,
      created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
    );
  `);

  logger.info('Database schema initialized');
}

// ============================================================
// INTERNAL HELPERS
// ============================================================

function _assertSafeSql(sql) {
  // Block comment injection and stacked queries
  if (/\/\*[\s\S]*?\*\//.test(sql))
    throw new DatabaseError('SQL comments are not allowed.');
  if ((sql.match(/;/g) || []).length > 1)
    throw new DatabaseError('Multiple statements are not allowed.');
}

function _handleDbError(err, sql, paramKeys) {
  logger.error('Database query failed', {
    // Log the SQL template and key names — never the values
    sql_template: sql.replace(/\s+/g, ' ').trim(),
    param_keys:   paramKeys,
    error_code:   err.code,
  }, err);

  if (env.isDebug()) throw err;
  throw new DatabaseError('A database error occurred. Please try again.');
}

module.exports = {
  getDb, initSchema,
  queryAll, queryOne, execute,
  insertRow, updateRows,
  withTransaction,
  auditLog,
  assertTable, assertOrderCol,
  maskRow, maskRows,
};
