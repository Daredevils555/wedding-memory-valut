/**
 * api/health.js
 * GET /api/health
 *
 * Health check endpoint for:
 *   - Vercel deployment verification
 *   - Uptime monitoring (e.g. UptimeRobot, Checkly)
 *   - Cloudflare health check probe
 *
 * Tests: API reachability, Supabase connectivity.
 * Returns: HTTP 200 (healthy) or HTTP 503 (degraded/down).
 *
 * Security: Public endpoint, no auth required.
 *           Rate-limited to prevent abuse.
 *           Never exposes secrets or internal details.
 */
'use strict';
 
const { withMiddleware, ok, err } = require('../lib/middleware');
const { getAdminClient }          = require('../lib/supabase');
 
const handler = async (req, res) => {
  const startTime = Date.now();
  const checks    = {};
 
  // ── DATABASE PING ────────────────────────────────────────────────
  try {
    const db = getAdminClient();
    // Lightweight query — no table scan
    const { error } = await db.from('contact_information').select('id').limit(1).maybeSingle();
    checks.database = error ? 'degraded' : 'ok';
  } catch (e) {
    checks.database = 'down';
    console.error('[Health] Database check failed:', e.message);
  }
 
  const latencyMs = Date.now() - startTime;
  const allOk     = Object.values(checks).every(v => v === 'ok');
  const status    = allOk ? 200 : 503;
 
  return res.status(status).json({
    status:    allOk ? 'ok' : 'degraded',
    timestamp: new Date().toISOString(),
    latencyMs,
    version:   '5.0.0',
    checks,
  });
};
 
module.exports = withMiddleware(handler, {
  methods:   ['GET'],
  rateLimit: { max: 30, windowSecs: 60, key: 'health' },
});
 