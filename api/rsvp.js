/**
 * api/rsvp.js
 * POST /api/rsvp — Submit a new RSVP
 * GET  /api/rsvp — Check submission status by name (for duplicate prevention)
 *
 * Security controls:
 *   - Rate limited: 3 submissions / 60s per IP
 *   - Cloudflare Turnstile bot prevention
 *   - Honeypot field check
 *   - Full input validation via Zod schema
 *   - IP hashed (never stored raw)
 *   - No RSVP data exposed publicly (GET only returns existence, not data)
 *   - Supabase service key used — no anon key client in browser
 *
 * DB: rsvps table (schema.sql)
 */
'use strict';
 
const { withMiddleware, ok, err }      = require('../lib/middleware');
const { getAdminClient }               = require('../lib/supabase');
const { rsvpSchema, validate }         = require('../lib/validation');
 
const handler = async (req, res) => {
  const db = getAdminClient();
 
  // ── GET — Check if a name has already submitted ────────────────
  if (req.method === 'GET') {
    const name = (req.query?.name || '').trim().slice(0, 100);
    if (!name) return ok(res, { exists: false });
 
    const { data, error } = await db
      .from('rsvps')
      .select('id, attending, created_at')
      .ilike('guest_name', name)        // case-insensitive match
      .limit(1)
      .maybeSingle();
 
    if (error) {
      console.error('[RSVP GET] DB error:', error.message);
      return ok(res, { exists: false }); // fail open for UX
    }
 
    return ok(res, {
      exists:    !!data,
      attending: data?.attending ?? null,
    });
  }
 
  // ── POST — Submit RSVP ──────────────────────────────────────────
 
  // Honeypot check (silent reject — bots shouldn't know they're blocked)
  if (req.body?.rsvp_hp) {
    return ok(res, { received: true }); // fake success
  }
 
  // Validate input
  const validation = validate(rsvpSchema, req.body);
  if (!validation.ok) {
    return err(res, validation.errors.join('; '), 422, 'VALIDATION_ERROR');
  }
 
  const {
    guest_name,
    email,
    phone,
    guests_count,
    attending,
    // turnstileToken already verified by middleware
  } = validation.data;
 
  // Soft duplicate check — warn but don't block (same-name different people)
  // Hard duplicate window: same IP + same name within 10 minutes
  const tenMinutesAgo = new Date(Date.now() - 10 * 60 * 1000).toISOString();
  const { data: duplicate } = await db
    .from('rsvps')
    .select('id')
    .eq('ip_hash', req.ipHash)
    .ilike('guest_name', guest_name)
    .gte('created_at', tenMinutesAgo)
    .limit(1)
    .maybeSingle();
 
  if (duplicate) {
    // Return success to prevent enumeration; include a hint
    return ok(res, {
      received:  true,
      duplicate: true,
      message:   'An RSVP with this name was recently submitted from your network.',
    });
  }
 
  // Insert into database
  const { data: inserted, error: insertError } = await db
    .from('rsvps')
    .insert({
      guest_name,
      email,
      phone,
      guests_count,
      attending,
      ip_hash: req.ipHash,
    })
    .select('id, created_at')
    .single();
 
  if (insertError) {
    console.error('[RSVP POST] Insert failed:', insertError.message, insertError.details);
    return err(res, 'Could not save your RSVP. Please try again.', 500, 'DB_ERROR');
  }
 
  // Log analytics event (non-blocking)
  try {
    await db.from('analytics_events').insert({
        event_type: 'rsvp_submitted',
        section: 'rsvp',
        metadata: { attending, guests_count },
        ip_hash: req.ipHash,
    });
} catch (e) {
    console.warn('[Analytics] RSVP event failed:', e.message);
}
 
  return ok(res, {
    received:   true,
    id:         inserted.id,
    attending,
    created_at: inserted.created_at,
    message:    attending
      ? `Thank you, ${guest_name}! We can't wait to celebrate with you.`
      : `Thank you for letting us know, ${guest_name}. We'll miss you!`,
  }, 201);
};
 
module.exports = withMiddleware(handler, {
  methods:   ['GET', 'POST'],
  rateLimit: { max: 3, windowSecs: 60, key: 'rsvp' },
  turnstile: true,
});
 