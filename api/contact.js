/**
 * api/contact.js
 * GET /api/contact — Return active contact information
 *
 * Returns all active contact records ordered by display_order.
 * Used by the Contact section on the wedding site.
 *
 * Security controls:
 *   - Public read, no auth required
 *   - Only is_active=true records returned
 *   - Response cached at CDN edge (60s)
 *   - Rate limited to prevent scraping
 *   - Sensitive fields never exposed (ip_hash, internal IDs not needed)
 *
 * DB: contact_information table (schema.sql)
 */
'use strict';
 
const { withMiddleware, ok, err } = require('../lib/middleware');
const { getAdminClient }          = require('../lib/supabase');
 
const handler = async (req, res) => {
  const db = getAdminClient();
 
  const { data, error } = await db
    .from('contact_information')
    .select('id, role, display_name, phone, whatsapp, email, description, display_order, is_emergency')
    .eq('is_active', true)
    .order('display_order', { ascending: true });
 
  if (error) {
    console.error('[Contact GET] DB error:', error.message);
    return err(res, 'Could not load contact information.', 500, 'DB_ERROR');
  }
 
  // Cache at CDN edge for 60 seconds — contact info rarely changes
  res.setHeader('Cache-Control', 'public, max-age=60, stale-while-revalidate=300');
 
  return ok(res, { contacts: data || [] });
};
 
module.exports = withMiddleware(handler, {
  methods:   ['GET'],
  rateLimit: { max: 30, windowSecs: 60, key: 'contact' },
});
 