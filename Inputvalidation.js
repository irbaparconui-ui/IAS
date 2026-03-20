
'use strict';

const { ValidationError } = require('./errorHandler');

const Sanitizer = {
  // Escape for safe HTML output
  escapeHtml(str) {
    return String(str)
      .replace(/&/g,  '&amp;')
      .replace(/</g,  '&lt;')
      .replace(/>/g,  '&gt;')
      .replace(/"/g,  '&quot;')
      .replace(/'/g,  '&#x27;')
      .replace(/\//g, '&#x2F;');
  },

  // Escape for safe JS string insertion
  escapeJs(str) {
    return JSON.stringify(str)
      .replace(/<\/script>/gi, '<\\/script>')
      .slice(1, -1);   // Remove surrounding quotes
  },

  // Remove null bytes, normalize whitespace
  clean(str) {
    return String(str)
      .replace(/\x00/g, '')          // null bytes
      .replace(/\r\n/g, '\n')        // normalize CRLF
      .replace(/\r/g,   '\n')
      .trim();
  },

  // Safe filename (prevent path traversal)
  safeFilename(name) {
    let safe = require('path').basename(name);           // strip dirs
    safe = safe.replace(/[^a-zA-Z0-9._\-]/g, '_');      // safe chars only
    safe = safe.replace(/^\.+/, '');                     // no leading dots
    return safe || 'file';
  },
};

// ============================================================
// DETECTOR — input-side threat scanning
// ============================================================

const XSS_PATTERNS = [
  /<script/i, /javascript:/i, /onerror\s*=/i, /onload\s*=/i,
  /eval\s*\(/i, /document\.cookie/i, /<iframe/i, /vbscript:/i,
];

const SQLI_PATTERNS = [
  /\bUNION\b.{0,30}\bSELECT\b/i,
  /\bDROP\b.{0,10}\bTABLE\b/i,
  /\bINSERT\b.{0,10}\bINTO\b/i,
  /;\s*(DROP|DELETE|UPDATE|INSERT|EXEC)\b/i,
  /--\s/,
];

const Detector = {
  hasXss(val)  { return XSS_PATTERNS.some(p => p.test(String(val))); },
  hasSqli(val) { return SQLI_PATTERNS.some(p => p.test(String(val))); },
  hasPathTraversal(val) { return /\.\.[\\/]/.test(String(val)); },
};

// ============================================================
// RULES — individual validators
// ============================================================

const Rules = {
  required:   (v)      => (v !== undefined && v !== null && v !== '') || 'Field is required.',
  string:     (v)      => typeof v === 'string'                        || 'Must be a string.',
  number:     (v)      => typeof v === 'number' && !isNaN(v)          || 'Must be a number.',
  boolean:    (v)      => typeof v === 'boolean'                       || 'Must be a boolean.',

  min:        (n)      => (v) => (Number(v) >= n)                      || `Must be at least ${n}.`,
  max:        (n)      => (v) => (Number(v) <= n)                      || `Must not exceed ${n}.`,
  minLength:  (n)      => (v) => (String(v).length >= n)               || `Must be at least ${n} characters.`,
  maxLength:  (n)      => (v) => (String(v).length <= n)               || `Must not exceed ${n} characters.`,

  email:      (v)      => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)        || 'Must be a valid email address.',
  url:        (v)      => { try { new URL(v); return true; } catch { return 'Must be a valid URL.'; } },
  integer:    (v)      => Number.isInteger(Number(v))                  || 'Must be an integer.',
  alphaNum:   (v)      => /^[a-zA-Z0-9]+$/.test(v)                    || 'Must contain only letters and numbers.',
  alphaNumUs: (v)      => /^[a-zA-Z0-9_]+$/.test(v)                   || 'Must contain only letters, numbers, and underscores.',
  uuid:       (v)      => /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(v) || 'Must be a valid UUID.',

  in:         (...opts) => (v) => opts.includes(String(v))              || `Must be one of: ${opts.join(', ')}.`,
  notIn:      (...opts) => (v) => !opts.includes(String(v))             || 'Value is not permitted.',

  noXss:      (v)      => !Detector.hasXss(v)                          || 'Input contains unsafe content.',
  noSqli:     (v)      => !Detector.hasSqli(v)                         || 'Input contains suspicious patterns.',
  noTraversal:(v)      => !Detector.hasPathTraversal(v)                 || 'Input contains path traversal sequences.',

  password:   (v) => {
    const errs = [];
    if (String(v).length < 8)                     errs.push('8+ characters');
    if (!/[A-Z]/.test(v))                         errs.push('an uppercase letter');
    if (!/[a-z]/.test(v))                         errs.push('a lowercase letter');
    if (!/[0-9]/.test(v))                         errs.push('a number');
    if (!/[^a-zA-Z0-9]/.test(v))                  errs.push('a special character');
    if (/password|123456|qwerty/i.test(v))         errs.push('no common passwords');
    return errs.length === 0 || `Password must contain: ${errs.join(', ')}.`;
  },

  fileExt: (...allowed) => (v) => {
    const ext = String(v).split('.').pop().toLowerCase();
    return allowed.includes(ext) || `File extension must be one of: ${allowed.join(', ')}.`;
  },

  mime: (...allowed) => (v) => {
    return allowed.includes(String(v).split(';')[0].trim())
      || `MIME type not allowed. Allowed: ${allowed.join(', ')}.`;
  },
};

// ============================================================
// VALIDATOR — runs a schema against a data object
// ============================================================

function validate(data, schema) {
  const errors = {};

  for (const [field, ruleList] of Object.entries(schema)) {
    const value = data?.[field];
    const fieldErrors = [];

    for (const rule of ruleList) {
      const result = rule(value);
      if (result !== true) fieldErrors.push(result);
    }

    if (fieldErrors.length) errors[field] = fieldErrors;
  }

  if (Object.keys(errors).length) {
    throw new ValidationError('Validation failed.', { fields: errors });
  }

  // Return sanitized copy
  const sanitized = {};
  for (const field of Object.keys(schema)) {
    if (data?.[field] !== undefined) {
      sanitized[field] = typeof data[field] === 'string'
        ? Sanitizer.clean(data[field])
        : data[field];
    }
  }
  return sanitized;
}

// ============================================================
// EXPRESS MIDDLEWARE FACTORY
// ============================================================

// Usage: router.post('/register', validate(registerSchema), handler)
function validateMiddleware(schema) {
  return (req, res, next) => {
    try {
      req.validated = validate(req.body, schema);
      next();
    } catch (err) {
      next(err);
    }
  };
}

// ============================================================
// COMMON SCHEMAS  (reusable across routes)
// ============================================================

const schemas = {
  register: {
    username: [Rules.required, Rules.string, Rules.alphaNumUs, Rules.minLength(3), Rules.maxLength(30), Rules.noXss],
    email:    [Rules.required, Rules.string, Rules.email,    Rules.maxLength(255)],
    password: [Rules.required, Rules.string, Rules.password],
  },

  login: {
    email:    [Rules.required, Rules.string, Rules.email],
    password: [Rules.required, Rules.string, Rules.minLength(1), Rules.maxLength(128)],
  },

  updateProfile: {
    display_name: [Rules.required, Rules.string, Rules.minLength(1), Rules.maxLength(80),   Rules.noXss, Rules.noSqli],
    bio:          [Rules.required, Rules.string, Rules.maxLength(500), Rules.noXss],
  },

  createProduct: {
    name:        [Rules.required, Rules.string, Rules.minLength(1), Rules.maxLength(200), Rules.noXss, Rules.noSqli],
    price:       [Rules.required, Rules.number, Rules.min(0),       Rules.max(1_000_000)],
    stock:       [Rules.required, Rules.integer, Rules.min(0),      Rules.max(100_000)],
  },
};

module.exports = {
  Sanitizer, Detector, Rules,
  validate, validateMiddleware, schemas,
};
