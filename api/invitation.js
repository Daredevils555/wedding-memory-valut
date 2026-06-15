/**
 * api/invitation.js
 * GET /api/invitation
 *
 * Returns all invitation assets from the `invitation_assets` table,
 * sorted by display_order then page_number. Assets are stored in
 * Supabase Storage (invitations bucket) and managed via the admin
 * dashboard. Supports PDF, JPG, PNG, and WebP.
 *
 * Response is cached at the CDN edge for 5 minutes — invitation
 * files change rarely and this eliminates DB round-trips during
 * wedding-day traffic spikes.
 */

'use strict';

const { withMiddleware, ok, err } = require('../lib/middleware');
const { getAdminClient }          = require('../lib/supabase');

const handler = async (req, res) => {
  const db = getAdminClient();

  const { data, error } = await db
    .from('invitation_assets')
    .select(
      'id, label, public_url, mime_type, file_size, page_number, is_primary, display_order, created_at'
    )
    .order('display_order', { ascending: true })
    .order('page_number',   { ascending: true });

  if (error) {
    console.error('[Invitation GET] DB error:', error.message);
    return err(res, 'Could not load invitation assets.', 500, 'DB_ERROR');
  }

  // Separate primary asset from supporting pages
  const primary    = (data || []).find(a => a.is_primary) || (data || [])[0] || null;
  const allAssets  = data || [];

  // Cache at CDN edge — 5 min fresh, 30 min stale-while-revalidate
  res.setHeader('Cache-Control', 'public, max-age=300, stale-while-revalidate=1800');

  return ok(res, {
    primary,
    assets:      allAssets,
    totalPages:  allAssets.length,
    hasInvitation: allAssets.length > 0,
  });
};

module.exports = withMiddleware(handler, {
  methods:   ['GET'],
  rateLimit: { max: 60, windowSecs: 60, key: 'invitation' },
});