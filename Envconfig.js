
'use strict';

const fs   = require('fs');
const path = require('path');

// ── Internal store (isolated from process.env) ──────────────
const _env = {};

// ── Load & parse .env ───────────────────────────────────────
function load(filePath = path.resolve(process.cwd(), '.env')) {
  if (!fs.existsSync(filePath)) {
    throw new Error(
      `[ENV] .env file not found at: ${filePath}\n` +
      `      Copy .env.example → .env and fill in values.`
    );
  }

  const lines = fs.readFileSync(filePath, 'utf8').split('\n');

  for (const raw of lines) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;       // skip comments/blank
    if (!line.includes('='))          continue;       // skip malformed

    const eqIdx = line.indexOf('=');
    const key   = line.slice(0, eqIdx).trim();
    let   val   = line.slice(eqIdx + 1).trim();

    // Strip surrounding quotes (single or double)
    if ((val.startsWith('"') && val.endsWith('"')) ||
        (val.startsWith("'") && val.endsWith("'"))) {
      val = val.slice(1, -1);
    }

    _env[key] = val;
  }
}

// ── Validate required keys ───────────────────────────────────
function requireKeys(keys) {
  const missing = keys.filter(k => !_env[k] || _env[k].trim() === '');
  if (missing.length) {
    throw new Error(
      `[ENV] Missing required environment variables:\n` +
      missing.map(k => `      • ${k}`).join('\n')
    );
  }
}

// ── Typed accessors ──────────────────────────────────────────
const get     = (key, def = undefined)  => _env[key] ?? def;
const str     = (key, def = '')         => String(_env[key] ?? def);
const num     = (key, def = 0)          => Number(_env[key] ?? def);
const bool    = (key, def = false)      => {
  const v = (_env[key] ?? String(def)).toLowerCase();
  return ['true','1','yes','on'].includes(v);
};

// ── isProduction / isDebug ───────────────────────────────────
const isProduction = () => str('NODE_ENV', 'production') === 'production';
const isDebug      = () => {
  if (isProduction()) return false;    // NEVER debug in production
  return bool('APP_DEBUG', false);
};

// ── Safe summary (no secrets) ────────────────────────────────
function summary() {
  return {
    APP_NAME:  str('APP_NAME'),
    NODE_ENV:  str('NODE_ENV', 'production'),
    APP_DEBUG: isDebug(),
    APP_HOST:  str('APP_HOST', '127.0.0.1'),
    APP_PORT:  num('APP_PORT', 3000),
    DB_ENGINE: str('DB_ENGINE', 'sqlite'),
    LOG_LEVEL: str('LOG_LEVEL', 'error'),
    // Secrets intentionally excluded
  };
}

// ── Bootstrap (called once in app.js) ───────────────────────
function init() {
  load();
  requireKeys([
    'APP_SECRET_KEY',
    'JWT_SECRET',
    'DB_NAME',
  ]);
  return summary();
}

module.exports = { init, get, str, num, bool, isProduction, isDebug, summary };
