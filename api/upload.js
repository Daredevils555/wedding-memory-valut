/**
 * api/upload.js
 * POST /api/upload
 *
 * Memory wall image upload. Accepts base64-encoded image data,
 * validates magic bytes, processes through Sharp (strip EXIF,
 * resize, optimise), stores in Supabase Storage, inserts a row
 * in the `memories` table, returns the public URL.
 *
 * Vercel body parser raised to 10 MB so a 5 MB source image
 * (~6.8 MB base64) fits comfortably inside the JSON envelope.
 */

'use strict';

const crypto    = require('crypto');
const sharp     = require('sharp');
const { withMiddleware, ok, err } = require('../lib/middleware');
const { getAdminClient, logAdminAction } = require('../lib/supabase');
const { uploadSchema, validate }         = require('../lib/validation');

// ── CONSTANTS ────────────────────────────────────────────────────────

const BUCKET        = 'memories';
const MAX_DIMENSION = 1600;   // px — longest side
const MAX_SRC_BYTES = 5 * 1024 * 1024;          // 5 MB raw
const MAX_B64_CHARS = Math.ceil(MAX_SRC_BYTES * 1.38) + 100; // ~7 MB b64

// Magic-byte signatures
const MAGIC = {
  'image/jpeg': [[0xFF, 0xD8, 0xFF]],
  'image/png':  [[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]],
  'image/webp': null,   // checked separately (RIFF…WEBP)
};

// ── HELPERS ──────────────────────────────────────────────────────────

/**
 * Strip the optional "data:image/…;base64," prefix and return a Buffer.
 */
const decodeBase64 = (raw) => {
  const comma = raw.indexOf(',');
  const b64   = comma !== -1 ? raw.slice(comma + 1) : raw;
  return Buffer.from(b64.replace(/\s/g, ''), 'base64');
};

/**
 * Validate magic bytes for JPEG, PNG, WebP.
 * Returns true if the buffer header matches the declared mimeType.
 */
const validateMagicBytes = (buf, mimeType) => {
  if (buf.length < 12) return false;

  if (mimeType === 'image/jpeg') {
    return buf[0] === 0xFF && buf[1] === 0xD8 && buf[2] === 0xFF;
  }

  if (mimeType === 'image/png') {
    const sig = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    return sig.every((b, i) => buf[i] === b);
  }

  if (mimeType === 'image/webp') {
    // RIFF????WEBP
    const riff = buf.slice(0, 4).toString('ascii');
    const webp = buf.slice(8, 12).toString('ascii');
    return riff === 'RIFF' && webp === 'WEBP';
  }

  return false;
};

/**
 * Build a collision-resistant storage path.
 * Format: memories/YYYY/MM/<uuid>.webp
 */
const buildStoragePath = () => {
  const now   = new Date();
  const year  = now.getUTCFullYear();
  const month = String(now.getUTCMonth() + 1).padStart(2, '0');
  const uid   = crypto.randomUUID();
  return `memories/${year}/${month}/${uid}.webp`;
};

/**
 * Process the image with Sharp:
 *   • Auto-rotate (honour EXIF orientation then strip all metadata)
 *   • Resize to MAX_DIMENSION on the longest side
 *   • Convert to WebP at quality 82
 */
const processImage = async (buf) => {
  const processed = await sharp(buf)
    .rotate()                           // auto-rotate from EXIF, then EXIF stripped
    .resize(MAX_DIMENSION, MAX_DIMENSION, {
      fit:                'inside',     // never upscale
      withoutEnlargement: true,
    })
    .webp({
      quality:  82,
      effort:   4,                      // encoder effort: 0-6 (4 is a good balance)
      lossless: false,
    })
    .withMetadata(false)                // strip all EXIF / GPS / XMP
    .toBuffer({ resolveWithObject: true });

  return {
    data:     processed.data,
    size:     processed.data.length,
    info:     processed.info,           // { width, height, … }
  };
};

// ── HANDLER ──────────────────────────────────────────────────────────

const handler = async (req, res) => {
  // ── Honeypot (silent reject) ──────────────────────────────────────
  if (req.body?.hp_field) {
    return ok(res, { received: true });
  }

  // ── Input validation ─────────────────────────────────────────────
  const validation = validate(uploadSchema, req.body);
  if (!validation.ok) {
    return err(res, validation.errors.join('; '), 422, 'VALIDATION_ERROR');
  }

  const { imageData, mimeType, authorName, caption } = validation.data;

  // ── Decode + size guard ───────────────────────────────────────────
  if (imageData.length > MAX_B64_CHARS) {
    return err(res, 'Image data exceeds the 5 MB limit.', 413, 'FILE_TOO_LARGE');
  }

  let rawBuffer;
  try {
    rawBuffer = decodeBase64(imageData);
  } catch {
    return err(res, 'Could not decode image data.', 400, 'DECODE_ERROR');
  }

  if (rawBuffer.length > MAX_SRC_BYTES) {
    return err(res, 'Decoded image exceeds the 5 MB limit.', 413, 'FILE_TOO_LARGE');
  }

  if (rawBuffer.length < 8) {
    return err(res, 'Image file is too small or corrupted.', 400, 'INVALID_IMAGE');
  }

  // ── Magic-bytes validation ────────────────────────────────────────
  if (!validateMagicBytes(rawBuffer, mimeType)) {
    return err(
      res,
      'Image content does not match the declared file type. Upload a valid JPEG, PNG, or WebP.',
      400,
      'INVALID_MAGIC_BYTES',
    );
  }

  // ── Image processing via Sharp ────────────────────────────────────
  let processed;
  try {
    processed = await processImage(rawBuffer);
  } catch (sharpErr) {
    console.error('[Upload] Sharp processing failed:', sharpErr.message);
    return err(res, 'Image could not be processed. Please try a different photo.', 422, 'PROCESSING_ERROR');
  }

  // ── Build storage path ────────────────────────────────────────────
  const storagePath = buildStoragePath();

  // ── Upload to Supabase Storage ────────────────────────────────────
  const db = getAdminClient();

  const { error: storageError } = await db.storage
    .from(BUCKET)
    .upload(storagePath, processed.data, {
      contentType:  'image/webp',
      cacheControl: '31536000',          // 1-year immutable cache
      upsert:       false,
    });

  if (storageError) {
    console.error('[Upload] Storage error:', storageError.message);
    return err(res, 'Could not store the image. Please try again.', 500, 'STORAGE_ERROR');
  }

  // ── Get public URL ────────────────────────────────────────────────
  const { data: { publicUrl } } = db.storage
    .from(BUCKET)
    .getPublicUrl(storagePath);

  // ── Insert memories row ───────────────────────────────────────────
  const { data: memory, error: dbError } = await db
    .from('memories')
    .insert({
      author_name:  authorName  || null,
      caption:      caption     || null,
      storage_path: storagePath,
      public_url:   publicUrl,
      file_size:    processed.size,
      mime_type:    'image/webp',         // always stored as webp after processing
      is_approved:  true,
      ip_hash:      req.ipHash || null,
    })
    .select('id, public_url, author_name, caption, created_at')
    .single();

  if (dbError) {
    // Row insert failed — attempt to clean up the orphaned storage object
    console.error('[Upload] DB insert failed:', dbError.message);
    db.storage.from(BUCKET).remove([storagePath]).catch(e =>
      console.error('[Upload] Storage cleanup failed:', e.message)
    );
    return err(res, 'Could not save your memory. Please try again.', 500, 'DB_ERROR');
  }

  // ── Analytics event (non-blocking) ───────────────────────────────
  try {
    await db.from('analytics_events').insert({
        event_type: 'memory_uploaded',
        section: 'memories',
        metadata: {
            file_size_kb: Math.round(processed.size / 1024),
            width: processed.info.width,
            height: processed.info.height,
        },
        ip_hash: req.ipHash || null,
    });
} catch (e) {
    console.warn('[Analytics] Memory event failed:', e.message);
}
  return ok(res, {
    id:         memory.id,
    publicUrl:  memory.public_url,
    authorName: memory.author_name,
    caption:    memory.caption,
    createdAt:  memory.created_at,
  }, 201);
};

// ── EXPORT ───────────────────────────────────────────────────────────

const wrapped = withMiddleware(handler, {
  methods:   ['POST'],
  rateLimit: { max: 10, windowSecs: 300, key: 'upload' }, // 10 uploads per 5 min per IP
  turnstile: true,
});

// Raise Vercel's body-parser limit so the base64 JSON envelope fits.
// Default is 4.5 MB; 10 MB covers a 5 MB source image (~6.8 MB base64) with headroom.
wrapped.config = {
  api: {
    bodyParser: {
      sizeLimit: '10mb',
    },
  },
};

module.exports = wrapped;
