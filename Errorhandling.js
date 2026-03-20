
'use strict';

const fs   = require('fs');
const path = require('path');
const env  = require('./environment');

// ── Exception Hierarchy ──────────────────────────────────────
class AppError extends Error {
  constructor(message, statusCode = 500, context = {}) {
    super(message);
    this.name       = this.constructor.name;
    this.statusCode = statusCode;
    this.context    = context;
    this.isOperational = true;   // Distinguish from programmer errors
    Error.captureStackTrace(this, this.constructor);
  }
}

class AuthError       extends AppError { constructor(m, ctx) { super(m, 401, ctx); } }
class ForbiddenError  extends AppError { constructor(m, ctx) { super(m, 403, ctx); } }
class NotFoundError   extends AppError { constructor(m, ctx) { super(m, 404, ctx); } }
class ValidationError extends AppError { constructor(m, ctx) { super(m, 422, ctx); } }
class RateLimitError  extends AppError { constructor(m, ctx) { super(m, 429, ctx); } }
class DatabaseError   extends AppError { constructor(m, ctx) { super(m, 500, ctx); } }

// ── Safe public messages (no internal detail) ────────────────
const SAFE_MESSAGES = {
  400: 'The request was invalid or malformed.',
  401: 'Authentication is required.',
  403: 'You do not have permission to perform this action.',
  404: 'The requested resource was not found.',
  422: 'The submitted data failed validation.',
  429: 'Too many requests. Please slow down.',
  500: 'An internal server error occurred.',
  503: 'The service is temporarily unavailable.',
};

// ── Unique error ID ──────────────────────────────────────────
function generateErrorId() {
  const bytes = require('crypto').randomBytes(6);
  return bytes.toString('hex').toUpperCase();
}

// ── Structured Logger ────────────────────────────────────────
const SCRUB_KEYS = new Set([
  'password','passwd','secret','token','authorization',
  'cookie','api_key','apikey','credit_card','ssn',
]);

function scrub(obj) {
  if (!obj || typeof obj !== 'object') return obj;
  const out = {};
  for (const [k, v] of Object.entries(obj)) {
    out[k] = SCRUB_KEYS.has(k.toLowerCase())
      ? '[REDACTED]'
      : (typeof v === 'object' ? scrub(v) : v);
  }
  return out;
}

function sanitizePath(str) {
  if (typeof str !== 'string') return str;
  return str.replace(process.cwd(), '[project]');
}

let _logStream = null;

function getLogStream() {
  if (_logStream) return _logStream;
  const logFile = env.str('LOG_FILE', 'app.log');
  const logDir  = path.dirname(path.resolve(logFile));
  fs.mkdirSync(logDir, { recursive: true });
  _logStream = fs.createWriteStream(path.resolve(logFile), { flags: 'a' });
  return _logStream;
}

function writeLog(level, message, context = {}) {
  const minLevels = { DEBUG:0, INFO:1, WARNING:2, ERROR:3, CRITICAL:4 };
  const min = minLevels[env.str('LOG_LEVEL','ERROR').toUpperCase()] ?? 3;
  if ((minLevels[level] ?? 0) < min) return;

  const entry = JSON.stringify({
    timestamp: new Date().toISOString(),
    level,
    message,
    context:   scrub(context),
  });

  getLogStream().write(entry + '\n');
  if (env.isDebug()) process.stdout.write(`[${level}] ${message}\n`);
}

const logger = {
  debug:    (msg, ctx) => writeLog('DEBUG',    msg, ctx),
  info:     (msg, ctx) => writeLog('INFO',     msg, ctx),
  warning:  (msg, ctx) => writeLog('WARNING',  msg, ctx),
  error:    (msg, ctx, err) => writeLog('ERROR', msg, {
    ...ctx,
    ...(err ? {
      exception: err.constructor.name,
      // Sanitize paths from traces in all envs, only include in debug
      trace: env.isDebug()
        ? sanitizePath(err.stack || '')
        : '[hidden in production]',
    } : {}),
  }),
  critical: (msg, ctx) => writeLog('CRITICAL', msg, ctx),
};

// ── Express Middleware ───────────────────────────────────────

// 404 catcher — place after all routes
function notFoundMiddleware(req, res, next) {
  next(new NotFoundError(`Route ${req.method} ${req.path} not found.`));
}

// Global error handler — place last in app
function errorMiddleware(err, req, res, next) {                // eslint-disable-line no-unused-vars
  const errorId    = generateErrorId();
  const statusCode = err.statusCode || 500;
  const debug      = env.isDebug();

  logger.error(err.message, {
    error_id:  errorId,
    status:    statusCode,
    path:      req.path,
    method:    req.method,
    ...(err.context || {}),
  }, err);

  const body = {
    error:    true,
    code:     statusCode,
    error_id: errorId,
    message:  SAFE_MESSAGES[statusCode] || SAFE_MESSAGES[500],
  };

  // Only expose detail in development
  if (debug && err.isOperational) {
    body.detail = err.message;
    if (err.context && Object.keys(err.context).length)
      body.context = scrub(err.context);
  }

  res
    .status(statusCode)
    .set('Content-Type', 'application/json')
    .json(body);
}

module.exports = {
  AppError, AuthError, ForbiddenError, NotFoundError,
  ValidationError, RateLimitError, DatabaseError,
  logger, generateErrorId,
  notFoundMiddleware, errorMiddleware,
};
