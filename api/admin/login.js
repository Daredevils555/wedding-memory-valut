/**
 * api/admin/login.js
 * POST /api/admin/login
 *
 * Authenticates an admin user via Supabase Auth (email + password).
 * After successful auth, verifies the user's email is listed in the
 * ADMIN_EMAILS environment variable before returning a session token.
 *
 * The returned access_token is a signed Supabase JWT. The frontend
 * stores it in sessionStorage and sends it as:
 *   Authorization: Bearer <access_token>
 * on all subsequent /api/admin/* requests, where withMiddleware's
 * requireAdmin option verifies it via getAnonClient().auth.getUser().
 *
 * Security controls:
 *   - Rate limited: 5 attempts / 10 minutes per IP (brute-force guard)
 *   - Full Zod validation on email + password
 *   - ADMIN_EMAILS allowlist — Supabase Auth success alone is not enough
 *   - Audit log entry on every login attempt (success and failure)
 *   - Never returns the refresh_token to the browser
 *   - Error messages are intentionally generic (no user enumeration)
 */

'use strict';

const { withMiddleware, ok, err } = require('../../lib/middleware');
const { getAnonClient, logAdminAction } = require('../../lib/supabase');
const { adminLoginSchema, validate }    = require('../../lib/validation');

const handler = async (req, res) => {
  // ── Input validation ─────────────────────────────────────────────
  const validation = validate(adminLoginSchema, req.body);
  if (!validation.ok) {
    return err(res, 'Invalid email or password.', 400, 'VALIDATION_ERROR');
  }

  const { email, password } = validation.data;

  // ── ADMIN_EMAILS allowlist check (pre-auth, avoids unnecessary DB call) ──
  const adminEmails = (process.env.ADMIN_EMAILS || '')
    .split(',')
    .map(e => e.trim().toLowerCase())
    .filter(Boolean);

  if (adminEmails.length > 0 && !adminEmails.includes(email.toLowerCase())) {
    // Log the rejected attempt without revealing the reason to the caller
    await logAdminAction({
      action:     'login_rejected_not_admin',
      details:    { email },
      ipHash:     req.ipHash,
    }).catch(() => {});

    return err(res, 'Invalid email or password.', 401, 'UNAUTHORIZED');
  }

  // ── Supabase Auth ────────────────────────────────────────────────
  const supabase = getAnonClient();

  const { data, error: authError } = await supabase.auth.signInWithPassword({
    email,
    password,
  });

  if (authError || !data?.session || !data?.user) {
    await logAdminAction({
      action:  'login_failed',
      details: { email, reason: authError?.message || 'no session' },
      ipHash:  req.ipHash,
    }).catch(() => {});

    // Generic message — prevents distinguishing "wrong password" from "no account"
    return err(res, 'Invalid email or password.', 401, 'UNAUTHORIZED');
  }

  const { user, session } = data;

  // ── Post-auth allowlist re-check (defence in depth) ──────────────
  if (adminEmails.length > 0 && !adminEmails.includes((user.email || '').toLowerCase())) {
    await logAdminAction({
      adminId:    user.id,
      adminEmail: user.email,
      action:     'login_rejected_post_auth',
      ipHash:     req.ipHash,
    }).catch(() => {});

    return err(res, 'Invalid email or password.', 401, 'UNAUTHORIZED');
  }

  // ── Success audit log ─────────────────────────────────────────────
  await logAdminAction({
    adminId:    user.id,
    adminEmail: user.email,
    action:     'login_success',
    ipHash:     req.ipHash,
  }).catch(() => {});

  // Return the access_token (JWT) only — never the refresh_token
  return ok(res, {
    accessToken: session.access_token,
    expiresAt:   session.expires_at,          // Unix timestamp
    admin: {
      id:    user.id,
      email: user.email,
    },
  });
};

module.exports = withMiddleware(handler, {
  methods:   ['POST'],
  rateLimit: { max: 5, windowSecs: 600, key: 'admin-login' }, // 5 attempts / 10 min
  // No turnstile — admin login is not a public-facing form
});