/**
 * lib/validation.js
 * Zod validation schemas for every API endpoint.
 * Import the schema you need and call .safeParse(body).
 */
'use strict';
 
const { z } = require('zod');
 
// ── SHARED PRIMITIVES ────────────────────────────────────────────────
 
const trimmedString = (min = 1, max = 500) =>
  z.string().trim().min(min).max(max);
 
const optionalString = (max = 200) =>
  z.string().trim().max(max).optional().nullable().transform(v => v || null);
 
const phoneNumber = z
  .string()
  .trim()
  .max(25)
  .regex(/^[+\d\s\-().]{5,25}$/, 'Invalid phone number format')
  .optional()
  .nullable()
  .transform(v => v || null);
 
const emailAddress = z
  .string()
  .trim()
  .email('Invalid email address')
  .max(254)
  .optional()
  .nullable()
  .transform(v => v || null);
 
// ── RSVP ─────────────────────────────────────────────────────────────
 
const MEAL_OPTIONS = ['no-preference', 'vegetarian', 'non-vegetarian', 'vegan', 'jain'];
 
const rsvpSchema = z.object({
  guest_name: trimmedString(1, 100),
 
  email:   emailAddress,
  phone:   phoneNumber,
 
  guests_count: z
    .number({ coerce: true })
    .int()
    .min(1, 'At least 1 guest required')
    .max(20, 'Maximum 20 guests per RSVP')
    .default(1),
 
  attending: z
    .boolean({ coerce: true, invalid_type_error: 'attending must be true or false' }),
 
  meal_preference: z
    .enum(MEAL_OPTIONS)
    .optional()
    .nullable()
    .transform(v => v || null),
 
  notes: z
    .string()
    .trim()
    .max(500)
    .optional()
    .nullable()
    .transform(v => v || null),
 
  // Honeypot — must be absent or empty
  rsvp_hp: z.string().max(0).optional(),
 
  // Cloudflare Turnstile
  turnstileToken: z.string().optional(),
});
 
// ── BLESSING ─────────────────────────────────────────────────────────
 
const blessingSchema = z.object({
  name: trimmedString(1, 80),
 
  relation: z
    .string()
    .trim()
    .max(60)
    .optional()
    .nullable()
    .transform(v => v || null),
 
  message: trimmedString(1, 500),
 
  // Honeypot
  blessing_hp: z.string().max(0).optional(),
 
  // Turnstile
  turnstileToken: z.string().optional(),
});
 
// ── SUPPORT REQUEST ───────────────────────────────────────────────────
 
const SUPPORT_CATEGORIES = ['directions', 'meal', 'accommodation', 'general', 'other'];
 
const supportSchema = z.object({
  name:     trimmedString(1, 100),
  phone:    phoneNumber,
  email:    emailAddress,
  category: z.enum(SUPPORT_CATEGORIES).default('general'),
  message:  trimmedString(5, 1000),
 
  // Honeypot
  support_hp: z.string().max(0).optional(),
});
 
// ── MEMORY WALL UPLOAD ────────────────────────────────────────────────
 
const ALLOWED_MIME_TYPES = ['image/jpeg', 'image/png', 'image/webp'];
const MAX_FILE_BYTES      = 5 * 1024 * 1024; // 5 MB
 
const uploadSchema = z.object({
  // Base64-encoded image data (data URI or raw base64)
  imageData: z
    .string()
    .min(100, 'Image data too small')
    .max(8_000_000, 'Image data too large (max ~6 MB base64)')
    .refine(v => /^(data:image\/(jpeg|png|webp);base64,)?[A-Za-z0-9+/]+=*$/.test(v.replace(/\n/g, '')), 'Invalid base64 image data'),
 
  mimeType: z.enum(ALLOWED_MIME_TYPES, {
    errorMap: () => ({ message: 'Only JPEG, PNG, and WebP images are accepted' }),
  }),
 
  authorName: z
    .string()
    .trim()
    .max(60)
    .optional()
    .nullable()
    .transform(v => v || null),
 
  caption: z
    .string()
    .trim()
    .max(200)
    .optional()
    .nullable()
    .transform(v => v || null),
});
 
// ── CONTACT INFORMATION (Admin) ───────────────────────────────────────
 
const contactInfoSchema = z.object({
  role: trimmedString(1, 60),
 
  display_name: trimmedString(1, 100),
 
  phone:    phoneNumber,
  whatsapp: phoneNumber,
  email:    emailAddress,
 
  description: optionalString(300),
 
  display_order: z
    .number({ coerce: true })
    .int()
    .min(0)
    .max(999)
    .default(0),
 
  is_emergency: z.boolean().default(false),
  is_active:    z.boolean().default(true),
});
 
const contactInfoUpdateSchema = contactInfoSchema.partial().extend({
  id: z.string().uuid('Invalid contact ID'),
});
 
// ── ADMIN LOGIN ───────────────────────────────────────────────────────
 
const adminLoginSchema = z.object({
  email:    z.string().trim().email('Invalid email').max(254),
  password: z.string().min(8, 'Password too short').max(256),
});
 
// ── PAGINATION ────────────────────────────────────────────────────────
 
const paginationSchema = z.object({
  page:  z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(20),
});
 
// ── HELPERS ───────────────────────────────────────────────────────────
 
/**
 * validate(schema, data)
 * Returns { ok: true, data } or { ok: false, errors: string[] }
 */
const validate = (schema, data) => {
  const result = schema.safeParse(data);
  if (result.success) {
    return { ok: true, data: result.data };
  }
  const errors = result.error.issues.map(i => `${i.path.join('.')}: ${i.message}`);
  return { ok: false, errors };
};
 
module.exports = {
  rsvpSchema,
  blessingSchema,
  supportSchema,
  uploadSchema,
  contactInfoSchema,
  contactInfoUpdateSchema,
  adminLoginSchema,
  paginationSchema,
  validate,
  ALLOWED_MIME_TYPES,
  MAX_FILE_BYTES,
};
 