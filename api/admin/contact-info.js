/**
 * api/admin/contact-info.js
 * GET  /api/admin/contact-info
 * POST /api/admin/contact-info
 *
 * Admin management of the contact_information table.
 * Requires a valid admin JWT (Authorization: Bearer <token>).
 *
 * GET:
 *   Returns ALL contact records (active and inactive), ordered by
 *   display_order. Public /api/contact only returns is_active=true.
 *
 * POST:
 *   Body without "id"  → creates a new contact record (contactInfoSchema)
 *   Body with "id"     → updates an existing record (contactInfoUpdateSchema)
 *
 *   Supports partial updates — e.g. send only { id, is_active: false }
 *   to disable a contact, or { id, is_emergency: true, whatsapp: '...' }
 *   to flag an emergency contact and set its WhatsApp number.
 *
 * Security controls:
 *   - requireAdmin: true — JWT verified + ADMIN_EMAILS allowlist
 *   - Full Zod validation on every field
 *   - Every create/update is recorded in admin_logs (audit trail)
 *   - Rate limited: 60 requests / 60 s per IP
 */

'use strict';

const { withMiddleware, ok, err }     = require('../../lib/middleware');
const { getAdminClient, logAdminAction } = require('../../lib/supabase');
const {
  contactInfoSchema,
  contactInfoUpdateSchema,
  validate,
} = require('../../lib/validation');

const handler = async (req, res) => {
  const db = getAdminClient();

  // No caching — admin data must always be fresh
  res.setHeader('Cache-Control', 'no-store');

  // ── GET — list all contacts (active + inactive) ──────────────────
  if (req.method === 'GET') {
    const { data, error } = await db
      .from('contact_information')
      .select(
        'id, role, display_name, phone, whatsapp, email, description, display_order, is_emergency, is_active, created_at, updated_at'
      )
      .order('display_order', { ascending: true });

    if (error) {
      console.error('[AdminContact GET] DB error:', error.message);
      return err(res, 'Could not load contact information.', 500, 'DB_ERROR');
    }

    return ok(res, { contacts: data || [] });
  }

  // ── POST — create or update a contact ─────────────────────────────

  const hasId = !!req.body?.id;

  // ── UPDATE (id present) ───────────────────────────────────────────
  if (hasId) {
    const validation = validate(contactInfoUpdateSchema, req.body);
    if (!validation.ok) {
      return err(res, validation.errors.join('; '), 422, 'VALIDATION_ERROR');
    }

    const { id, ...fields } = validation.data;

    if (Object.keys(fields).length === 0) {
      return err(res, 'No fields provided to update.', 400, 'NO_FIELDS');
    }

    const { data: updated, error: updateError } = await db
      .from('contact_information')
      .update(fields)
      .eq('id', id)
      .select(
        'id, role, display_name, phone, whatsapp, email, description, display_order, is_emergency, is_active, updated_at'
      )
      .single();

    if (updateError) {
      if (updateError.code === 'PGRST116') {
        return err(res, 'Contact not found.', 404, 'NOT_FOUND');
      }
      console.error('[AdminContact POST/update] DB error:', updateError.message);
      return err(res, 'Could not update contact.', 500, 'DB_ERROR');
    }

    await logAdminAction({
      adminId:    req.adminUser?.id,
      adminEmail: req.adminUser?.email,
      action:     'contact_updated',
      targetType: 'contact_information',
      targetId:   id,
      details:    fields,
      ipHash:     req.ipHash,
    });

    return ok(res, { contact: updated });
  }

  // ── CREATE (no id) ─────────────────────────────────────────────────
  const validation = validate(contactInfoSchema, req.body);
  if (!validation.ok) {
    return err(res, validation.errors.join('; '), 422, 'VALIDATION_ERROR');
  }

  const { data: inserted, error: insertError } = await db
    .from('contact_information')
    .insert(validation.data)
    .select(
      'id, role, display_name, phone, whatsapp, email, description, display_order, is_emergency, is_active, created_at'
    )
    .single();

  if (insertError) {
    console.error('[AdminContact POST/create] DB error:', insertError.message);
    return err(res, 'Could not create contact.', 500, 'DB_ERROR');
  }

  await logAdminAction({
    adminId:    req.adminUser?.id,
    adminEmail: req.adminUser?.email,
    action:     'contact_created',
    targetType: 'contact_information',
    targetId:   inserted.id,
    details:    validation.data,
    ipHash:     req.ipHash,
  });

  return ok(res, { contact: inserted }, 201);
};

module.exports = withMiddleware(handler, {
  methods:      ['GET', 'POST'],
  requireAdmin: true,
  rateLimit:    { max: 60, windowSecs: 60, key: 'admin-contact-info' },
});