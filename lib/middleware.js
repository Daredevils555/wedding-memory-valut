/**
 * lib/middleware.js
 * Shared middleware utilities for all API endpoints.
 * Handles: CORS, security headers, rate limiting, Turnstile, admin auth.
 */
'use strict';
 
const crypto = require('crypto');
const { getAnonClient } = require('./supabase');
 
// ── CONFIGURATION ────────────────────────────────────────────────────
const ALLOWED_ORIGINS = [
  ...(process.env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean),
  process.env.SITE_URL,
  // Allow localhost in development
  ...(process.env.NODE_ENV !== 'production' ? ['http://localhost:3000', 'http://localhost:3001'] : []),
].filter(Boolean);
 
// ── SECURITY HEADERS ─────────────────────────────────────────────────
const setSecurityHeaders = (res) => {
  res.setHeader('X-Content-Type-Options',   'nosniff');
  res.setHeader('X-Frame-Options',           'DENY');
  res.setHeader('Referrer-Policy',           'strict-origin-when-cross-origin');
  res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');
};
 
// ── CORS ─────────────────────────────────────────────────────────────
const setCorsHeaders = (req, res) => {
  const origin = req.headers.origin || '';
  if (ALLOWED_ORIGINS.includes(origin) || ALLOWED_ORIGINS.length === 0) {
    res.setHeader('Access-Control-Allow-Origin',  origin || '*');
    res.setHeader('Vary', 'Origin');
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Max-Age',        '86400');
};
 
// ── IP HASHING ───────────────────────────────────────────────────────
const hashIP = (req) => {
  const ip =
    req.headers['cf-connecting-ip'] ||
    req.headers['x-real-ip'] ||
    (req.headers['x-forwarded-for'] || '').split(',')[0].trim() ||
    req.socket?.remoteAddress ||
    'unknown';
  const salt = process.env.IP_SALT || 'default-salt-change-in-production';
  return crypto
    .createHash('sha256')
    .update(ip + salt)
    .digest('hex')
    .slice(0, 16);
};
 
// ── IN-MEMORY RATE LIMITER ────────────────────────────────────────────
// NOTE: For multi-instance / high traffic, replace with Upstash Redis.
// See: https://upstash.com/docs/redis/sdks/ratelimit
const _store = new Map();
 
const checkRateLimit = (identifier, maxRequests = 5, windowSeconds = 60) => {
  const now       = Date.now();
  const windowMs  = windowSeconds * 1000;
  const existing  = (_store.get(identifier) || []).filter(t => now - t < windowMs);
 
  if (existing.length >= maxRequests) {
    const resetAt = existing[0] + windowMs;
    return { allowed: false, remaining: 0, resetIn: Math.ceil((resetAt - now) / 1000) };
  }
 
  existing.push(now);
  _store.set(identifier, existing);
 
  // Probabilistic cleanup — avoid memory leak in long-running containers
  if (Math.random() < 0.02) {
    for (const [k, v] of _store.entries()) {
      if (!v.some(t => now - t < windowMs)) _store.delete(k);
    }
  }
 
  return { allowed: true, remaining: maxRequests - existing.length, resetIn: 0 };
};
 
// ── CLOUDFLARE TURNSTILE VERIFICATION ────────────────────────────────
const verifyTurnstile = async (token, ip) => {
  const secret = process.env.TURNSTILE_SECRET_KEY;
  if (!secret) {
    // Turnstile not configured — skip verification (dev/staging)
    console.warn('[Turnstile] TURNSTILE_SECRET_KEY not set; skipping verification.');
    return true;
  }
  if (!token || typeof token !== 'string' || token.length > 2048) return false;
 
  const form = new URLSearchParams();
  form.append('secret',   secret);
  form.append('response', token);
  if (ip) form.append('remoteip', ip);
 
  try {
    const resp = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method:  'POST',
      body:    form,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      signal:  AbortSignal.timeout(5000),
    });
    if (!resp.ok) return false;
    const data = await resp.json();
    return data.success === true;
  } catch (err) {
    console.error('[Turnstile] Verification failed:', err.message);
    return false; // fail closed
  }
};
 
// ── ADMIN JWT VERIFICATION ────────────────────────────────────────────
const verifyAdmin = async (req) => {
  const authHeader = req.headers.authorization || '';
  if (!authHeader.startsWith('Bearer ')) return null;
 
  const token = authHeader.slice(7).trim();
  if (!token) return null;
 
  try {
    const supabase = getAnonClient();
    const { data: { user }, error } = await supabase.auth.getUser(token);
    if (error || !user) return null;
 
    // RBAC: check if email is in the admin list
    const adminEmails = (process.env.ADMIN_EMAILS || '')
      .split(',')
      .map(e => e.trim().toLowerCase())
      .filter(Boolean);
 
    if (!adminEmails.includes((user.email || '').toLowerCase())) return null;
 
    return user;
  } catch (err) {
    console.error('[AdminAuth] Token verification failed:', err.message);
    return null;
  }
};
 
// ── RESPONSE HELPERS ─────────────────────────────────────────────────
const ok = (res, data, status = 200) =>
  res.status(status).json({ success: true, data });
 
const err = (res, message, status = 400, code = null) =>
  res.status(status).json({ success: false, error: message, ...(code && { code }) });
 
// ── BODY PARSER ───────────────────────────────────────────────────────
const parseBody = (req) => {
  return new Promise((resolve, reject) => {
    if (req.body && typeof req.body === 'object') {
      return resolve(req.body); // Already parsed by Vercel
    }
    let raw = '';
    req.on('data', chunk => {
      raw += chunk.toString();
      if (raw.length > 65536) { // 64 KB limit
        reject(new Error('Request body too large'));
      }
    });
    req.on('end', () => {
      try {
        resolve(raw ? JSON.parse(raw) : {});
      } catch {
        resolve({});
      }
    });
    req.on('error', reject);
  });
};
 
// ── MAIN HANDLER WRAPPER ─────────────────────────────────────────────
/**
 * withMiddleware(handler, options)
 *
 * options:
 *   methods:      string[]  — allowed HTTP methods
 *   rateLimit:    { max, windowSecs, key? } | false
 *   requireAdmin: boolean   — verify admin JWT
 *   turnstile:    boolean   — verify Cloudflare Turnstile token in body
 */
const withMiddleware = (handler, options = {}) => {
  return async (req, res) => {
    setSecurityHeaders(res);
    setCorsHeaders(req, res);
 
    // Handle CORS preflight
    if (req.method === 'OPTIONS') return res.status(204).end();
 
    // Method check
    const allowed = options.methods || ['GET', 'POST'];
    if (!allowed.includes(req.method)) {
      res.setHeader('Allow', allowed.join(', '));
      return err(res, `Method ${req.method} not allowed`, 405, 'METHOD_NOT_ALLOWED');
    }
 
    // Parse body once
    if (['POST', 'PUT', 'PATCH'].includes(req.method)) {
      try {
        req.body = await parseBody(req);
      } catch {
        return err(res, 'Request body too large or malformed', 400, 'BAD_REQUEST');
      }
    }
 
    // Rate limiting
    if (options.rateLimit !== false) {
      const ipHash = hashIP(req);
      req.ipHash   = ipHash;
      const { max = 10, windowSecs = 60, key = req.url } = options.rateLimit || {};
      const rlKey  = `${ipHash}:${key}`;
      const result = checkRateLimit(rlKey, max, windowSecs);
      if (!result.allowed) {
        res.setHeader('Retry-After', String(result.resetIn));
        res.setHeader('X-RateLimit-Limit',     String(max));
        res.setHeader('X-RateLimit-Remaining', '0');
        return err(res, 'Too many requests. Please wait before trying again.', 429, 'RATE_LIMITED');
      }
      res.setHeader('X-RateLimit-Limit',     String(max));
      res.setHeader('X-RateLimit-Remaining', String(result.remaining));
    } else {
      req.ipHash = hashIP(req);
    }
 
    // Cloudflare Turnstile
    if (options.turnstile) {
      const token = req.body?.turnstileToken;
      const ip    = req.headers['cf-connecting-ip'] || '';
      const valid = await verifyTurnstile(token, ip);
      if (!valid) {
        return err(res, 'Bot challenge failed. Please refresh and try again.', 403, 'TURNSTILE_FAILED');
      }
    }
 
    // Admin authentication
    if (options.requireAdmin) {
      const user = await verifyAdmin(req);
      if (!user) {
        return err(res, 'Unauthorized', 401, 'UNAUTHORIZED');
      }
      req.adminUser = user;
    }
 
    // Execute handler
    try {
      await handler(req, res);
    } catch (error) {
      console.error(`[API] Unhandled error in ${req.method} ${req.url}:`, error);
      if (!res.headersSent) {
        err(res, 'An internal error occurred. Please try again.', 500, 'INTERNAL_ERROR');
      }
    }
  };
};
 
module.exports = {
  setSecurityHeaders,
  setCorsHeaders,
  hashIP,
  checkRateLimit,
  verifyTurnstile,
  verifyAdmin,
  parseBody,
  ok,
  err,
  withMiddleware,
};
 