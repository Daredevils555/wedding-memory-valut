/**
 * api/admin/data.js
 * GET /api/admin/data
 *
 * Returns dashboard statistics and paginated data for the admin panel.
 * Requires a valid admin JWT (Authorization: Bearer <token>).
 *
 * Query parameters:
 *   view        — 'summary' | 'rsvps' | 'blessings' | 'memories' | 'support'  (default: summary)
 *   page        — page number, 1-based                                          (default: 1)
 *   limit       — rows per page, max 100                                        (default: 50)
 *   attending   — 'true' | 'false' | '' — filter RSVPs by attendance
 *   search      — text search on guest name / blessing name
 *   status      — support request status: 'open' | 'in-progress' | 'resolved'
 *   approved    — 'true' | 'false' — filter memories / blessings by approval
 *
 * Security controls:
 *   - requireAdmin: true — JWT verified + ADMIN_EMAILS allowlist
 *   - Rate limited: 120 requests / 60 s per IP
 *   - No sensitive fields leaked (ip_hash stripped from all responses)
 *   - Uses service-key client — bypasses RLS safely on the backend only
 */

'use strict';

const { withMiddleware, ok, err } = require('../../lib/middleware');
const { getAdminClient }          = require('../../lib/supabase');
const { paginationSchema, validate } = require('../../lib/validation');

// ── HELPERS ──────────────────────────────────────────────────────────

const clamp = (n, min, max) => Math.min(Math.max(Number(n) || min, min), max);

const safeBool = (val) => {
  if (val === 'true'  || val === '1') return true;
  if (val === 'false' || val === '0') return false;
  return null;
};

// Strip ip_hash from every row — never sent to the browser
const strip = (rows) =>
  (rows || []).map(({ ip_hash, ...rest }) => rest);

// ── SUMMARY — parallel count queries ─────────────────────────────────

const getSummary = async (db) => {
  const [
    rsvpAll,
    rsvpYes,
    rsvpGuests,
    mealBreakdown,
    blessings,
    memories,
    supportOpen,
    supportAll,
  ] = await Promise.all([
    // Total RSVPs
    db.from('rsvps').select('id', { count: 'exact', head: true }),

    // Attending
    db.from('rsvps').select('id', { count: 'exact', head: true }).eq('attending', true),

    // Total guests attending (sum of guests_count)
    db.from('rsvps').select('guests_count').eq('attending', true),

    // Meal preference breakdown (attending only)
    db.from('rsvps')
      .select('meal_preference')
      .eq('attending', true)
      .not('meal_preference', 'is', null),

    // Blessings
    db.from('blessings').select('id', { count: 'exact', head: true }),

    // Memories
    db.from('memories').select('id', { count: 'exact', head: true }),

    // Open support requests
    db.from('support_requests').select('id', { count: 'exact', head: true }).eq('status', 'open'),

    // All support requests
    db.from('support_requests').select('id', { count: 'exact', head: true }),
  ]);

  // Aggregate guest count
  const totalGuests = (rsvpGuests.data || []).reduce(
    (sum, r) => sum + (parseInt(r.guests_count) || 0), 0
  );

  // Meal preference counts
  const meals = {};
  (mealBreakdown.data || []).forEach(({ meal_preference }) => {
    const k = meal_preference || 'no-preference';
    meals[k] = (meals[k] || 0) + 1;
  });

  const totalRsvps    = rsvpAll.count    || 0;
  const attendingYes  = rsvpYes.count    || 0;
  const attendingNo   = totalRsvps - attendingYes;
  const attendancePct = totalRsvps > 0
    ? Math.round((attendingYes / totalRsvps) * 100)
    : 0;

  return {
    rsvps: {
      total:         totalRsvps,
      attending:     attendingYes,
      declined:      attendingNo,
      totalGuests,
      attendancePct,
      mealBreakdown: meals,
    },
    blessings: {
      total: blessings.count || 0,
    },
    memories: {
      total: memories.count || 0,
    },
    support: {
      open:  supportOpen.count || 0,
      total: supportAll.count  || 0,
    },
  };
};

// ── RSVPS ─────────────────────────────────────────────────────────────

const getRsvps = async (db, { page, limit, attending, search }) => {
  const offset = (page - 1) * limit;

  let query = db
    .from('rsvps')
    .select(
      'id, guest_name, email, phone, guests_count, attending, meal_preference, notes, created_at',
      { count: 'exact' }
    )
    .order('created_at', { ascending: false })
    .range(offset, offset + limit - 1);

  const attendingBool = safeBool(attending);
  if (attendingBool !== null) query = query.eq('attending', attendingBool);

  if (search) {
    query = query.ilike('guest_name', %${search}%);
  }

  const { data, error, count } = await query;
  if (error) throw error;

  return {
    rows:       strip(data),
    total:      count || 0,
    page,
    limit,
    totalPages: Math.ceil((count || 0) / limit),
  };
};

// ── BLESSINGS ─────────────────────────────────────────────────────────

const getBlessings = async (db, { page, limit, approved, search }) => {
  const offset = (page - 1) * limit;

  let query = db
    .from('blessings')
    .select('id, name, relation, message, is_approved, created_at', { count: 'exact' })
    .order('created_at', { ascending: false })
    .range(offset, offset + limit - 1);

  const approvedBool = safeBool(approved);
  if (approvedBool !== null) query = query.eq('is_approved', approvedBool);

  if (search) query = query.ilike('name', %${search}%);

  const { data, error, count } = await query;
  if (error) throw error;

  return {
    rows:       strip(data),
    total:      count || 0,
    page,
    limit,
    totalPages: Math.ceil((count || 0) / limit),
  };
};

// ── MEMORIES ──────────────────────────────────────────────────────────

const getMemories = async (db, { page, limit, approved }) => {
  const offset = (page - 1) * limit;

  let query = db
    .from('memories')
    .select(
      'id, author_name, caption, public_url, file_size, mime_type, is_approved, created_at',
      { count: 'exact' }
    )
    .order('created_at', { ascending: false })
    .range(offset, offset + limit - 1);

  const approvedBool = safeBool(approved);
  if (approvedBool !== null) query = query.eq('is_approved', approvedBool);

  const { data, error, count } = await query;
  if (error) throw error;

  return {
    rows:       strip(data),
    total:      count || 0,
    page,
    limit,
    totalPages: Math.ceil((count || 0) / limit),
  };
};

// ── SUPPORT REQUESTS ──────────────────────────────────────────────────

const getSupport = async (db, { page, limit, status, search }) => {
  const offset = (page - 1) * limit;

  let query = db
    .from('support_requests')
    .select(
      'id, name, phone, email, category, message, status, created_at, updated_at',
      { count: 'exact' }
    )
    .order('created_at', { ascending: false })
    .range(offset, offset + limit - 1);

  const validStatuses = ['open', 'in-progress', 'resolved'];
  if (status && validStatuses.includes(status)) {
    query = query.eq('status', status);
  }

  if (search) query = query.ilike('name', %${search}%);

  const { data, error, count } = await query;
  if (error) throw error;

  return {
    rows:       strip(data),
    total:      count || 0,
    page,
    limit,
    totalPages: Math.ceil((count || 0) / limit),
  };
};

// ── HANDLER ───────────────────────────────────────────────────────────

const handler = async (req, res) => {
  const db = getAdminClient();
  const q  = req.query || {};

  const view   = ['summary', 'rsvps', 'blessings', 'memories', 'support'].includes(q.view)
    ? q.view
    : 'summary';

  const page   = clamp(q.page,  1, 9999);
  const limit  = clamp(q.limit, 1, 100);

  // No caching for admin data — must always be fresh
  res.setHeader('Cache-Control', 'no-store');

  try {
    if (view === 'summary') {
      const summary = await getSummary(db);
      return ok(res, { view: 'summary', summary });
    }

    if (view === 'rsvps') {
      const result = await getRsvps(db, {
        page, limit,
        attending: q.attending,
        search:    (q.search || '').trim().slice(0, 100),
      });
      return ok(res, { view: 'rsvps', ...result });
    }

    if (view === 'blessings') {
      const result = await getBlessings(db, {
        page, limit,
        approved: q.approved,
        search:   (q.search || '').trim().slice(0, 100),
      });
      return ok(res, { view: 'blessings', ...result });
    }

    if (view === 'memories') {
      const result = await getMemories(db, {
        page, limit,
        approved: q.approved,
      });
      return ok(res, { view: 'memories', ...result });
    }

    if (view === 'support') {
      const result = await getSupport(db, {
        page, limit,
        status: q.status,
        search: (q.search || '').trim().slice(0, 100),
      });
      return ok(res, { view: 'support', ...result });
    }

  } catch (e) {
    console.error([AdminData] Query failed (view=${view}):, e.message);
    return err(res, 'Could not fetch admin data.', 500, 'DB_ERROR');
  }
};

module.exports = withMiddleware(handler, {
  methods:      ['GET'],
  requireAdmin: true,
  rateLimit:    { max: 120, windowSecs: 60, key: 'admin-data' },
});