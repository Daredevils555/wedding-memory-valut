/**
 * api/blessings.js
 * GET  /api/blessings         — Fetch approved blessings (paginated)
 * POST /api/blessings         — Submit a new blessing
 *
 * Query params (GET):
 *   page  — page number (default: 1)
 *   limit — results per page (default: 20, max: 50)
 *
 * Security controls:
 *   - GET: public, read-only, only approved blessings returned
 *   - POST: rate limited (5/min per IP), Turnstile, honeypot, Zod validation
 *   - IP hashed — never stored raw
 *   - Content moderation: is_approved defaults to true; admin can revoke
 *
 * DB: blessings table (schema.sql)
 */
'use strict';
 
const { withMiddleware, ok, err } = require('../lib/middleware');
const { getAdminClient }          = require('../lib/supabase');
const { blessingSchema, paginationSchema, validate } = require('../lib/validation');
 
const handler = async (req, res) => {
  const db = getAdminClient();
 
  // ── GET — Fetch approved blessings ─────────────────────────────
  if (req.method === 'GET') {
    const pgResult = validate(paginationSchema, req.query || {});
    const { page = 1, limit = 20 } = pgResult.ok ? pgResult.data : {};
    const safeLimit = Math.min(limit, 50);
    const offset    = (page - 1) * safeLimit;
 
    const { data, error, count } = await db
      .from('blessings')
      .select('id, name, relation, message, created_at', { count: 'exact' })
      .eq('is_approved', true)
      .order('created_at', { ascending: false })
      .range(offset, offset + safeLimit - 1);
 
    if (error) {
      console.error('[Blessings GET] DB error:', error.message);
      return err(res, 'Could not load blessings.', 500, 'DB_ERROR');
    }
 
    // Cache for 30 seconds — fresh enough for real-time feel, reduces DB load
    res.setHeader('Cache-Control', 'public, max-age=30, stale-while-revalidate=60');
 
    return ok(res, {
      blessings:  data || [],
      total:      count || 0,
      page,
      limit:      safeLimit,
      totalPages: Math.ceil((count || 0) / safeLimit),
    });
  }
 
  // ── POST — Submit blessing ──────────────────────────────────────
 
  // Honeypot check
  if (req.body?.blessing_hp) {
    return ok(res, { received: true }); // silent bot rejection
  }
 
  const validation = validate(blessingSchema, req.body);
  if (!validation.ok) {
    return err(res, validation.errors.join('; '), 422, 'VALIDATION_ERROR');
  }
 
  const { name, relation, message } = validation.data;
 
  // Spam check: same IP, same message within 5 minutes
  const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000).toISOString();
  const { data: recent } = await db
    .from('blessings')
    .select('id')
    .eq('ip_hash', req.ipHash)
    .gte('created_at', fiveMinutesAgo)
    .limit(1)
    .maybeSingle();
 
  if (recent) {
    return ok(res, {
      received: true,
      message:  'Your blessing has already been received. Thank you!',
    });
  }
 
  const { data: inserted, error: insertError } = await db
    .from('blessings')
    .insert({ name, relation, message, ip_hash: req.ipHash, is_approved: true })
    .select('id, name, relation, message, created_at')
    .single();
 
  if (insertError) {
    console.error('[Blessings POST] Insert failed:', insertError.message);
    return err(res, 'Could not save your blessing. Please try again.', 500, 'DB_ERROR');
  }
 
  return ok(res, {
    received:  true,
    blessing:  { id: inserted.id, name: inserted.name, relation: inserted.relation, message: inserted.message, created_at: inserted.created_at },
    message:   'Your blessing has been received. Thank you!',
  }, 201);
};
 
module.exports = withMiddleware(handler, {
  methods:   ['GET', 'POST'],
  rateLimit: { max: 5, windowSecs: 60, key: 'blessings' },
  turnstile: true,
});
 