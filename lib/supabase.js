/**
 * lib/supabase.js
 * Supabase admin client — uses service key for full DB access.
 * This file is ONLY imported by backend API functions.
 * Never bundled or exposed to the browser.
 */
const { createClient } = require('@supabase/supabase-js');
 
let _adminClient = null;
let _anonClient  = null;
 
/**
 * getAdminClient()
 * Returns a Supabase client with the service role key.
 * Bypasses RLS — use only for trusted backend operations.
 */
const getAdminClient = () => {
  if (_adminClient) return _adminClient;
 
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
 
  if (!url || !key) {
    throw new Error(
      'Missing SUPABASE_URL or SUPABASE_SERVICE_KEY environment variables. ' +
      'Set them in Vercel → Project → Settings → Environment Variables.'
    );
  }
 
  _adminClient = createClient(url, key, {
    auth: {
      autoRefreshToken: false,
      persistSession:   false,
      detectSessionInUrl: false,
    },
    global: {
      headers: { 'x-application-name': 'wedding-platform-api' },
    },
  });
 
  return _adminClient;
};
 
/**
 * getAnonClient()
 * Returns a Supabase client with the anon key.
 * Used ONLY for auth.getUser() — verifying admin JWT tokens.
 */
const getAnonClient = () => {
  if (_anonClient) return _anonClient;
 
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_ANON_KEY;
 
  if (!url || !key) {
    throw new Error('Missing SUPABASE_URL or SUPABASE_ANON_KEY environment variables.');
  }
 
  _anonClient = createClient(url, key, {
    auth: {
      autoRefreshToken:  false,
      persistSession:    false,
      detectSessionInUrl: false,
    },
  });
 
  return _anonClient;
};
 
/**
 * logAdminAction()
 * Write an audit trail entry for all admin operations.
 */
const logAdminAction = async ({ adminId, adminEmail, action, targetType, targetId, details, ipHash }) => {
  try {
    const db = getAdminClient();
    await db.from('admin_logs').insert({
      admin_id:    adminId    || null,
      admin_email: adminEmail || null,
      action,
      target_type: targetType || null,
      target_id:   targetId   || null,
      details:     details    || null,
      ip_hash:     ipHash     || null,
    });
  } catch (err) {
    // Audit log failures should never block the main operation
    console.error('[AuditLog] Failed to write admin log:', err.message);
  }
};
 
module.exports = { getAdminClient, getAnonClient, logAdminAction };
 
