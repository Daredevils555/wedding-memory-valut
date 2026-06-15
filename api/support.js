/**
 * api/support.js
 * POST /api/support — Submit a guest support request
 *
 * Categories: directions, meal, accommodation, general, other
 *
 * Security controls:
 *   - Rate limited: 3 requests / 10 minutes per IP
 *   - Honeypot field
 *   - Full Zod validation
 *   - Duplicate submission prevention (same IP + category within 10 minutes)
 *   - IP hashed — not stored raw
 *   - No public GET — support requests are private to admin
 *
 * DB: support_requests table (schema.sql)
 */
'use strict';
 
const { withMiddleware, ok, err } = require('../lib/middleware');
const { getAdminClient }          = require('../lib/supabase');
const { supportSchema, validate } = require('../lib/validation');
 
const handler = async (req, res) => {
  const db = getAdminClient();
 
  // Honeypot
  if (req.body?.support_hp) {
    return ok(res, { received: true });
  }
 
  const validation = validate(supportSchema, req.body);
  if (!validation.ok) {
    return err(res, validation.errors.join('; '), 422, 'VALIDATION_ERROR');
  }
 
  const { name, phone, email, category, message } = validation.data;
 
  // Duplicate guard: same IP + same category in 10 minutes
  const tenMinutesAgo = new Date(Date.now() - 10 * 60 * 1000).toISOString();
  const { data: recent } = await db
    .from('support_requests')
    .select('id')
    .eq('ip_hash', req.ipHash)
    .eq('category', category)
    .gte('created_at', tenMinutesAgo)
    .limit(1)
    .maybeSingle();
 
  if (recent) {
    return ok(res, {
      received: true,
      message:  "We've received your request. Our team will be in touch shortly!",
    });
  }
 
  const { data: inserted, error: insertError } = await db
    .from('support_requests')
    .insert({ name, phone, email, category, message, ip_hash: req.ipHash, status: 'open' })
    .select('id, created_at')
    .single();
 
  if (insertError) {
    console.error('[Support POST] Insert failed:', insertError.message);
    return err(res, 'Could not submit your request. Please try again.', 500, 'DB_ERROR');
  }
 
  return ok(res, {
    received:  true,
    id:        inserted.id,
    message:   "We've received your request. Someone from the team will get back to you shortly!",
  }, 201);
};
 
module.exports = withMiddleware(handler, {
  methods:   ['POST'],
  rateLimit: { max: 3, windowSecs: 600, key: 'support' }, // 3 per 10 minutes
});
 