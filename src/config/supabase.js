const { createClient } = require('@supabase/supabase-js');
const { env } = require('./env');
const ws = require('ws');

// Node 20 no tiene WebSocket nativo — se lo pasamos manualmente al cliente de Realtime.
// Nosotros solo usamos Storage, pero el SDK lo inicializa igual.
const supabase = createClient(env.SUPABASE_URL, env.SUPABASE_SERVICE_ROLE_KEY, {
  realtime: { transport: ws },
  auth: { persistSession: false },
});

module.exports = { supabase };
