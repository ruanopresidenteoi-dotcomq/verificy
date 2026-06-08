function corsHeaders(env) {
  return {
    'Access-Control-Allow-Origin': env?.FRONTEND_URL || '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Credentials': 'true',
  };
}
function jsonResponse(data, status = 200, env) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders(env) },
  });
}
function errorResponse(status, message, env) {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders(env) },
  });
}
async function createJWT(payload, secret) {
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = btoa(JSON.stringify({ ...payload, iat: Date.now() }));
  const data = `${header}.${body}`;
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  return `${data}.${btoa(String.fromCharCode(...new Uint8Array(sig)))}`;
}
async function verifyJWT(token, secret) {
  try {
    const [header, body, sig] = token.split('.');
    const data = `${header}.${body}`;
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
    const valid = await crypto.subtle.verify('HMAC', key, Uint8Array.from(atob(sig), c => c.charCodeAt(0)), new TextEncoder().encode(data));
    if (!valid) return null;
    const p = JSON.parse(atob(body));
    if (p.exp && Date.now() > p.exp) return null;
    return p;
  } catch { return null; }
}
async function getUser(request, env) {
  const auth = request.headers.get('Authorization');
  if (!auth || !auth.startsWith('Bearer ')) return null;
  return verifyJWT(auth.slice(7), env.JWT_SECRET);
}
function generateCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let c = 'VCY-';
  for (let i = 0; i < 6; i++) c += chars[Math.floor(Math.random() * chars.length)];
  return c;
}
async function logAction(env, serverId, discordId, action, details) {
  try {
    await env.DB.prepare('INSERT INTO logs (server_id, discord_id, action, details) VALUES (?, ?, ?, ?)')
      .bind(serverId || 'system', discordId || null, action, JSON.stringify(details)).run();
  } catch {}
}
async function syncUser(discordId, guildId, env) {
  try {
    const dbUser = await env.DB.prepare('SELECT * FROM users WHERE discord_id = ?').bind(discordId).first();
    if (!dbUser || !dbUser.roblox_id || !dbUser.verified) return { success: false, error: 'Usuário não verificado' };
    const server = await env.DB.prepare('SELECT * FROM servers WHERE server_id = ?').bind(guildId).first();
    if (!server) return { success: false, error: 'Servidor não configurado' };
    const groups = await env.DB.prepare('SELECT * FROM groups WHERE server_id = ? ORDER BY priority DESC').bind(guildId).all();
    if (!groups.results.length) return { success: true, message: 'Nenhum grupo configurado', roles_to_add: [], roles_to_remove: [] };
    const mappings = await env.DB.prepare('SELECT * FROM role_mappings WHERE server_id = ?').bind(guildId).all();
    let rolesToAdd = [];
    let rolesToRemove = mappings.results.map(m => m.discord_role_id);
    let prefix = null;
    if (server.verified_role_id) rolesToAdd.push(server.verified_role_id);
    for (const group of groups.results) {
      try {
        const memberData = await (await fetch(`https://groups.roblox.com/v2/users/${dbUser.roblox_id}/groups/roles`)).json();
        if (!memberData.data) continue;
        const gm = memberData.data.find(g => String(g.group.id) === String(group.group_id));
        if (gm) {
          const rankId = String(gm.role.rank);
          const rankName = gm.role.name;
          const mapping = mappings.results.find(m => String(m.group_id) === String(group.group_id) && (String(m.roblox_rank_id) === rankId || m.roblox_rank_name === rankName));
          if (mapping) {
            rolesToAdd.push(mapping.discord_role_id);
            rolesToRemove = rolesToRemove.filter(r => r !== mapping.discord_role_id);
            if (mapping.prefix_type === 'auto') { const m2 = rankName.match(/\[(.+?)\]/); prefix = m2 ? `[${m2[1]}]` : null; }
            else if (mapping.prefix_type === 'manual' && mapping.prefix) prefix = mapping.prefix;
          }
          break;
        }
      } catch {}
    }
    const fmt = server.nickname_format || '{username}';
    const nickname = fmt.replace('{prefix}', prefix || '').replace('{username}', dbUser.roblox_username).replace('{display}', dbUser.roblox_display || dbUser.roblox_username).trim().replace(/\s+/g, ' ').slice(0, 32);
    const syncData = { discord_id: discordId, guild_id: guildId, roles_to_add: [...new Set(rolesToAdd)], roles_to_remove: [...new Set(rolesToRemove)], nickname, ts: Date.now() };
    await env.KV.put(`sync:apply:${guildId}:${discordId}`, JSON.stringify(syncData), { expirationTtl: 300 });
    await logAction(env, guildId, discordId, 'SYNC_QUEUED', syncData);
    return { success: true, ...syncData };
  } catch (err) { return { success: false, error: 'Erro ao sincronizar' }; }
}
async function handleAuth(path, method, request, env) {
  if (path === '/api/auth/discord/login' && method === 'GET') {
    const state = btoa(JSON.stringify({ ts: Date.now() }));
    const params = new URLSearchParams({ client_id: env.DISCORD_CLIENT_ID, redirect_uri: env.DISCORD_REDIRECT_URI, response_type: 'code', scope: 'identify guilds', state });
    return Response.redirect(`https://discord.com/oauth2/authorize?${params}`, 302);
  }
  if (path === '/api/auth/discord/callback' && method === 'GET') {
    const url = new URL(request.url);
    const code = url.searchParams.get('code');
    if (!code) return errorResponse(400, 'Código OAuth não encontrado', env);
    try {
      const tokenData = await (await fetch('https://discord.com/api/oauth2/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ client_id: env.DISCORD_CLIENT_ID, client_secret: env.DISCORD_CLIENT_SECRET, grant_type: 'authorization_code', code, redirect_uri: env.DISCORD_REDIRECT_URI }) })).json();
      if (!tokenData.access_token) return errorResponse(400, 'Falha ao obter token Discord', env);
      const discordUser = await (await fetch('https://discord.com/api/users/@me', { headers: { Authorization: `Bearer ${tokenData.access_token}` } })).json();
      const guilds = await (await fetch('https://discord.com/api/users/@me/guilds', { headers: { Authorization: `Bearer ${tokenData.access_token}` } })).json();
      const adminGuilds = guilds.filter(g => { const p = BigInt(g.permissions || 0); return (p & BigInt(0x20)) !== BigInt(0) || (p & BigInt(0x8)) !== BigInt(0); });
      await env.DB.prepare(`INSERT INTO users (discord_id, verified) VALUES (?, 0) ON CONFLICT(discord_id) DO UPDATE SET updated_at = datetime('now')`).bind(discordUser.id).run();
      const jwt = await createJWT({ discord_id: discordUser.id, discord_username: discordUser.username, discord_avatar: discordUser.avatar, exp: Date.now() + 7 * 24 * 60 * 60 * 1000 }, env.JWT_SECRET);
      await env.KV.put(`guilds:${discordUser.id}`, JSON.stringify(adminGuilds), { expirationTtl: 600 });
      return Response.redirect(`${env.FRONTEND_URL}/dashboard?token=${jwt}`, 302);
    } catch (err) { return errorResponse(500, 'Erro no login com Discord', env); }
  }
  if (path === '/api/auth/me' && method === 'GET') {
    const auth = request.headers.get('Authorization');
    if (!auth) return errorResponse(401, 'Não autenticado', env);
    const payload = await verifyJWT(auth.replace('Bearer ', ''), env.JWT_SECRET);
    if (!payload) return errorResponse(401, 'Token inválido', env);
    const user = await env.DB.prepare('SELECT * FROM users WHERE discord_id = ?').bind(payload.discord_id).first();
    const guildsRaw = await env.KV.get(`guilds:${payload.discord_id}`);
    const guilds = guildsRaw ? JSON.parse(guildsRaw) : [];
    return jsonResponse({ discord_id: payload.discord_id, username: payload.discord_username, avatar: payload.discord_avatar, verified: user?.verified || 0, roblox_id: user?.roblox_id, roblox_username: user?.roblox_username, guilds }, 200, env);
  }
  if (path === '/api/auth/select-server' && method === 'POST') {
    const user = await getUser(request, env);
    if (!user) return errorResponse(401, 'Não autenticado', env);
    const { guild_id } = await request.json();
    await env.DB.prepare('INSERT OR IGNORE INTO servers (server_id, owner_id) VALUES (?, ?)').bind(guild_id, user.discord_id).run();
    await env.KV.put(`selected_server:${user.discord_id}`, guild_id, { expirationTtl: 86400 });
    return jsonResponse({ success: true, guild_id }, 200, env);
  }
  return errorResponse(404, 'Rota auth não encontrada', env);
}
async function handleVerify(path, method, request, env) {
  if (path === '/api/verify/roblox/start' && method === 'GET') {
    const user = await getUser(request, env);
    if (!user) return errorResponse(401, 'Não autenticado', env);
    const params = new URLSearchParams({ client_id: env.ROBLOX_CLIENT_ID, redirect_uri: env.ROBLOX_REDIRECT_URI, response_type: 'code', scope: 'openid profile', state: user.discord_id });
    return jsonResponse({ url: `https://apis.roblox.com/oauth/v1/authorize?${params}` }, 200, env);
  }
  if (path === '/api/verify/roblox/callback' && method === 'GET') {
    const url = new URL(request.url);
    const code = url.searchParams.get('code');
    const discordId = url.searchParams.get('state');
    if (!code || !discordId) return errorResponse(400, 'Parâmetros inválidos', env);
    try {
      const tokenData = await (await fetch('https://apis.roblox.com/oauth/v1/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ client_id: env.ROBLOX_CLIENT_ID, client_secret: env.ROBLOX_CLIENT_SECRET, grant_type: 'authorization_code', code, redirect_uri: env.ROBLOX_REDIRECT_URI }) })).json();
      if (!tokenData.access_token) return errorResponse(400, 'Falha ao obter token Roblox', env);
      const robloxUser = await (await fetch('https://apis.roblox.com/oauth/v1/userinfo', { headers: { Authorization: `Bearer ${tokenData.access_token}` } })).json();
      const robloxId = robloxUser.sub;
      const username = robloxUser.preferred_username || robloxUser.name;
      const displayName = robloxUser.nickname || username;
      await env.DB.prepare(`UPDATE users SET roblox_id = ?, roblox_username = ?, roblox_display = ?, verified = 1, updated_at = datetime('now') WHERE discord_id = ?`).bind(robloxId, username, displayName, discordId).run();
      await env.DB.prepare('INSERT INTO verifications (discord_id, roblox_id, method) VALUES (?, ?, ?)').bind(discordId, robloxId, 'oauth').run();
      await env.KV.put(`sync:pending:${discordId}`, JSON.stringify({ discord_id: discordId, ts: Date.now() }), { expirationTtl: 300 });
      return Response.redirect(`${env.FRONTEND_URL}/verified?success=true`, 302);
    } catch { return Response.redirect(`${env.FRONTEND_URL}/verified?error=oauth_failed`, 302); }
  }
  if (path === '/api/verify/bio/generate' && method === 'POST') {
    const user = await getUser(request, env);
    if (!user) return errorResponse(401, 'Não autenticado', env);
    const code = generateCode();
    const expires = new Date(Date.now() + 15 * 60 * 1000).toISOString();
    await env.DB.prepare('INSERT OR REPLACE INTO bio_codes (discord_id, code, expires_at) VALUES (?, ?, ?)').bind(user.discord_id, code, expires).run();
    return jsonResponse({ code, expires_in: 900 }, 200, env);
  }
  if (path === '/api/verify/bio/check' && method === 'POST') {
    const user = await getUser(request, env);
    if (!user) return errorResponse(401, 'Não autenticado', env);
    const { roblox_username } = await request.json();
    if (!roblox_username) return errorResponse(400, 'Username Roblox é necessário', env);
    const bioCode = await env.DB.prepare('SELECT * FROM bio_codes WHERE discord_id = ?').bind(user.discord_id).first();
    if (!bioCode) return errorResponse(400, 'Nenhum código gerado', env);
    if (new Date(bioCode.expires_at) < new Date()) return errorResponse(400, 'Código expirado', env);
    try {
      const searchData = await (await fetch('https://users.roblox.com/v1/usernames/users', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ usernames: [roblox_username], excludeBannedUsers: true }) })).json();
      if (!searchData.data?.length) return errorResponse(404, 'Usuário Roblox não encontrado', env);
      const robloxId = searchData.data[0].id;
      const profile = await (await fetch(`https://users.roblox.com/v1/users/${robloxId}`)).json();
      if (!profile.description?.includes(bioCode.code)) return errorResponse(400, 'Código não encontrado na bio. Coloque o código na bio do Roblox e tente novamente.', env);
      await env.DB.prepare(`UPDATE users SET roblox_id = ?, roblox_username = ?, roblox_display = ?, verified = 1, updated_at = datetime('now') WHERE discord_id = ?`).bind(String(robloxId), profile.name, profile.displayName, user.discord_id).run();
      await env.DB.prepare('DELETE FROM bio_codes WHERE discord_id = ?').bind(user.discord_id).run();
      await env.DB.prepare('INSERT INTO verifications (discord_id, roblox_id, method) VALUES (?, ?, ?)').bind(user.discord_id, String(robloxId), 'bio').run();
      await env.KV.put(`sync:pending:${user.discord_id}`, JSON.stringify({ discord_id: user.discord_id, ts: Date.now() }), { expirationTtl: 300 });
      return jsonResponse({ success: true, roblox_id: robloxId, roblox_username: profile.name, roblox_display: profile.displayName }, 200, env);
    } catch { return errorResponse(500, 'Erro ao verificar bio', env); }
  }
  if (path === '/api/verify/status' && method === 'GET') {
    const user = await getUser(request, env);
    if (!user) return errorResponse(401, 'Não autenticado', env);
    const dbUser = await env.DB.prepare('SELECT * FROM users WHERE discord_id = ?').bind(user.discord_id).first();
    return jsonResponse({ verified: dbUser?.verified || 0, roblox_id: dbUser?.roblox_id, roblox_username: dbUser?.roblox_username, roblox_display: dbUser?.roblox_display }, 200, env);
  }
  return errorResponse(404, 'Rota verify não encontrada', env);
}
async function handleSync(path, method, request, env) {
  if (path === '/api/sync/user' && method === 'POST') {
    const user = await getUser(request, env);
    if (!user) return errorResponse(401, 'Não autenticado', env);
    const { guild_id } = await request.json();
    if (!guild_id) return errorResponse(400, 'guild_id é necessário', env);
    const result = await syncUser(user.discord_id, guild_id, env);
    return jsonResponse(result, result.success ? 200 : 400, env);
  }
  if (path === '/api/sync/server' && method === 'POST') {
    const user = await getUser(request, env);
    if (!user) return errorResponse(401, 'Não autenticado', env);
    const { guild_id } = await request.json();
    if (!guild_id) return errorResponse(400, 'guild_id é necessário', env);
    await env.KV.put(`sync:server:${guild_id}`, JSON.stringify({ requested_by: user.discord_id, ts: Date.now() }), { expirationTtl: 600 });
    await logAction(env, guild_id, user.discord_id, 'SYNC_SERVER_REQUESTED', {});
    return jsonResponse({ success: true, message: 'Sincronização em fila. O bot processará em instantes.' }, 200, env);
  }
  return errorResponse(404, 'Rota sync não encontrada', env);
}
async function handleGroups(path, method, request, env) {
  const user = await getUser(request, env);
  if (!user) return errorResponse(401, 'Não autenticado', env);
  const url = new URL(request.url);
  const guildId = url.searchParams.get('guild_id');
  if (!guildId) return errorResponse(400, 'guild_id é necessário', env);
  if (path === '/api/groups/ranks' && method === 'GET') {
    const groupId = url.searchParams.get('group_id');
    const data = await (await fetch(`https://groups.roblox.com/v1/groups/${groupId}/roles`)).json();
    return jsonResponse({ ranks: data.roles || [] }, 200, env);
  }
  if (method === 'GET') {
    const groups = await env.DB.prepare('SELECT * FROM groups WHERE server_id = ? ORDER BY priority DESC').bind(guildId).all();
    return jsonResponse({ groups: groups.results }, 200, env);
  }
  if (method === 'POST') {
    const { group_id } = await request.json();
    if (!group_id) return errorResponse(400, 'group_id é necessário', env);
    const server = await env.DB.prepare('SELECT * FROM servers WHERE server_id = ?').bind(guildId).first();
    if ((server?.plan || 'free') === 'free') {
      const count = await env.DB.prepare('SELECT COUNT(*) as c FROM groups WHERE server_id = ?').bind(guildId).first();
      if (count.c >= 2) return errorResponse(403, 'Limite de 2 grupos no plano gratuito.', env);
    }
    try {
      const rg = await (await fetch(`https://groups.roblox.com/v1/groups/${group_id}`)).json();
      if (rg.errors) return errorResponse(404, 'Grupo Roblox não encontrado', env);
      const existing = await env.DB.prepare('SELECT * FROM groups WHERE server_id = ? AND group_id = ?').bind(guildId, String(group_id)).first();
      if (existing) return errorResponse(400, 'Grupo já adicionado', env);
      await env.DB.prepare('INSERT INTO groups (server_id, group_id, group_name) VALUES (?, ?, ?)').bind(guildId, String(group_id), rg.name).run();
      return jsonResponse({ success: true, group: { id: group_id, name: rg.name, memberCount: rg.memberCount } }, 200, env);
    } catch { return errorResponse(500, 'Erro ao buscar grupo Roblox', env); }
  }
  if (method === 'DELETE') {
    const { group_id } = await request.json();
    await env.DB.prepare('DELETE FROM groups WHERE server_id = ? AND group_id = ?').bind(guildId, String(group_id)).run();
    await env.DB.prepare('DELETE FROM role_mappings WHERE server_id = ? AND group_id = ?').bind(guildId, String(group_id)).run();
    return jsonResponse({ success: true }, 200, env);
  }
  return errorResponse(404, 'Rota groups não encontrada', env);
}
async function handleRoles(path, method, request, env) {
  const user = await getUser(request, env);
  if (!user) return errorResponse(401, 'Não autenticado', env);
  const guildId = new URL(request.url).searchParams.get('guild_id');
  if (!guildId) return errorResponse(400, 'guild_id é necessário', env);
  if (method === 'GET') {
    const mappings = await env.DB.prepare('SELECT * FROM role_mappings WHERE server_id = ?').bind(guildId).all();
    return jsonResponse({ mappings: mappings.results }, 200, env);
  }
  if (method === 'POST') {
    const { group_id, roblox_rank_id, roblox_rank_name, discord_role_id, prefix, prefix_type } = await request.json();
    await env.DB.prepare('INSERT OR REPLACE INTO role_mappings (server_id, group_id, roblox_rank_id, roblox_rank_name, discord_role_id, prefix, prefix_type) VALUES (?, ?, ?, ?, ?, ?, ?)')
      .bind(guildId, group_id, roblox_rank_id, roblox_rank_name, discord_role_id, prefix || null, prefix_type || 'auto').run();
    return jsonResponse({ success: true }, 200, env);
  }
  if (method === 'DELETE') {
    const { group_id, roblox_rank_id } = await request.json();
    await env.DB.prepare('DELETE FROM role_mappings WHERE server_id = ? AND roblox_rank_id = ? AND group_id = ?').bind(guildId, roblox_rank_id, group_id).run();
    return jsonResponse({ success: true }, 200, env);
  }
  return errorResponse(404, 'Rota roles não encontrada', env);
}
async function handleDashboard(path, method, request, env) {
  const user = await getUser(request, env);
  if (!user) return errorResponse(401, 'Não autenticado', env);
  const guildId = new URL(request.url).searchParams.get('guild_id');
  if (path === '/api/dashboard/stats') {
    const [tv, ts, tg, vt] = await Promise.all([
      env.DB.prepare('SELECT COUNT(*) as c FROM users WHERE verified = 1').first(),
      env.DB.prepare('SELECT COUNT(*) as c FROM servers').first(),
      env.DB.prepare('SELECT COUNT(*) as c FROM groups').first(),
      env.DB.prepare("SELECT COUNT(*) as c FROM verifications WHERE date(created_at) = date('now')").first(),
    ]);
    const vw = await env.DB.prepare("SELECT date(created_at) as day, COUNT(*) as count FROM verifications WHERE created_at >= datetime('now', '-7 days') GROUP BY day ORDER BY day").all();
    return jsonResponse({ total_verified: tv?.c || 0, total_servers: ts?.c || 0, total_groups: tg?.c || 0, verified_today: vt?.c || 0, verified_week: vw.results || [] }, 200, env);
  }
  if (path === '/api/dashboard/server') {
    if (!guildId) return errorResponse(400, 'guild_id é necessário', env);
    if (method === 'GET') {
      const server = await env.DB.prepare('SELECT * FROM servers WHERE server_id = ?').bind(guildId).first();
      return jsonResponse({ server: server || null }, 200, env);
    }
    if (method === 'PUT') {
      const { verified_role_id, nickname_format } = await request.json();
      await env.DB.prepare('INSERT INTO servers (server_id, owner_id, verified_role_id, nickname_format) VALUES (?, ?, ?, ?) ON CONFLICT(server_id) DO UPDATE SET verified_role_id = excluded.verified_role_id, nickname_format = excluded.nickname_format')
        .bind(guildId, user.discord_id, verified_role_id || null, nickname_format || '{username}').run();
      return jsonResponse({ success: true }, 200, env);
    }
  }
  return errorResponse(404, 'Rota dashboard não encontrada', env);
}
async function handleLogs(path, method, request, env) {
  const user = await getUser(request, env);
  if (!user) return errorResponse(401, 'Não autenticado', env);
  const url = new URL(request.url);
  const guildId = url.searchParams.get('guild_id');
  const page = parseInt(url.searchParams.get('page') || '1');
  const offset = (page - 1) * 50;
  if (method === 'GET' && guildId) {
    const logs = await env.DB.prepare('SELECT * FROM logs WHERE server_id = ? ORDER BY created_at DESC LIMIT 50 OFFSET ?').bind(guildId, offset).all();
    const total = await env.DB.prepare('SELECT COUNT(*) as c FROM logs WHERE server_id = ?').bind(guildId).first();
    return jsonResponse({ logs: logs.results, total: total?.c || 0, page }, 200, env);
  }
  return errorResponse(404, 'Rota logs não encontrada', env);
}
async function handleBotRoutes(path, method, request, env) {
  if (request.headers.get('X-Bot-Secret') !== env.BOT_API_SECRET) return errorResponse(401, 'Bot secret inválido', env);
  if (path === '/api/bot/sync' && method === 'POST') {
    const { discord_id, guild_id } = await request.json();
    if (!discord_id || !guild_id) return errorResponse(400, 'discord_id e guild_id necessários', env);
    return jsonResponse(await syncUser(discord_id, guild_id, env), 200, env);
  }
  if (path === '/api/bot/userinfo' && method === 'GET') {
    const discordId = new URL(request.url).searchParams.get('discord_id');
    if (!discordId) return errorResponse(400, 'discord_id necessário', env);
    const user = await env.DB.prepare('SELECT * FROM users WHERE discord_id = ?').bind(discordId).first();
    if (!user) return errorResponse(404, 'Usuário não encontrado', env);
    const lv = await env.DB.prepare('SELECT method FROM verifications WHERE discord_id = ? ORDER BY created_at DESC LIMIT 1').bind(discordId).first();
    return jsonResponse({ discord_id: user.discord_id, roblox_id: user.roblox_id, roblox_username: user.roblox_username, roblox_display: user.roblox_display, verified: user.verified, method: lv?.method || null }, 200, env);
  }
  if (path === '/api/bot/pending-syncs' && method === 'GET') {
    const syncs = [];
    const sk = await env.KV.list({ prefix: 'sync:server:' });
    for (const key of sk.keys) { const v = await env.KV.get(key.name); if (v) { syncs.push({ type: 'server', guild_id: key.name.replace('sync:server:', ''), ...JSON.parse(v) }); await env.KV.delete(key.name); } }
    const uk = await env.KV.list({ prefix: 'sync:pending:' });
    for (const key of uk.keys) { const v = await env.KV.get(key.name); if (v) { syncs.push({ type: 'user', ...JSON.parse(v) }); await env.KV.delete(key.name); } }
    return jsonResponse({ syncs }, 200, env);
  }
  return errorResponse(404, 'Rota bot não encontrada', env);
}
function serveHTML() {
  return new Response(`<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>VerifiCy — Painel</title>
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700;800&family=DM+Sans:opsz,wght@9..40,300;9..40,400;9..40,500;9..40,600&display=swap" rel="stylesheet"/>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{--blue:#325CFE;--blue2:#4B8FFF;--bg:#0a0f2e;--bg2:#0f1640;--white:#fff;--muted:rgba(255,255,255,0.55);--card:rgba(255,255,255,0.05);--border:rgba(255,255,255,0.08);--success:#22c55e;--error:#ef4444}
html{scroll-behavior:smooth}
body{font-family:'DM Sans',sans-serif;background:var(--bg);color:var(--white);min-height:100vh;overflow-x:hidden}
body::before{content:'';position:fixed;inset:0;background:radial-gradient(ellipse 70% 50% at 15% 0%,rgba(50,92,254,.3) 0%,transparent 60%),radial-gradient(ellipse 50% 40% at 85% 100%,rgba(75,143,255,.15) 0%,transparent 60%);pointer-events:none;z-index:0}
#app{position:relative;z-index:1;min-height:100vh}
.topbar{display:flex;align-items:center;justify-content:space-between;padding:14px 5%;border-bottom:1px solid var(--border);background:rgba(10,15,46,.8);backdrop-filter:blur(20px);position:sticky;top:0;z-index:50}
.topbar-logo{display:flex;align-items:center;gap:10px;cursor:pointer}
.logo-text{font-family:'Syne',sans-serif;font-weight:800;font-size:1.2rem}
.topbar-right{display:flex;align-items:center;gap:14px}
.avatar{width:34px;height:34px;border-radius:50%;border:2px solid var(--blue);object-fit:cover}
.avatar-ph{width:34px;height:34px;border-radius:50%;background:var(--blue);display:flex;align-items:center;justify-content:center;font-weight:700;font-size:.85rem}
.user-name{font-size:.875rem;font-weight:500}
.btn-logout{background:transparent;border:1px solid var(--border);color:var(--muted);padding:7px 14px;border-radius:8px;cursor:pointer;font-size:.8rem;transition:all .2s}
.btn-logout:hover{border-color:rgba(255,255,255,.2);color:var(--white)}
.layout{display:flex;flex:1}
.sidebar{width:220px;background:var(--bg2);border-right:1px solid var(--border);padding:20px 0;flex-shrink:0;display:flex;flex-direction:column;gap:4px;min-height:calc(100vh - 65px)}
.sidebar-item{display:flex;align-items:center;gap:12px;padding:11px 20px;color:var(--muted);font-size:.875rem;font-weight:500;cursor:pointer;transition:all .2s;border-left:2px solid transparent}
.sidebar-item:hover{color:var(--white);background:rgba(255,255,255,.04)}
.sidebar-item.active{color:var(--white);background:rgba(50,92,254,.12);border-left-color:var(--blue)}
.sidebar-sep{padding:14px 16px 8px;font-size:.7rem;font-weight:600;letter-spacing:.1em;text-transform:uppercase;color:var(--muted)}
.content{flex:1;padding:32px 5%;overflow-y:auto}
h1.pt{font-family:'Syne',sans-serif;font-weight:800;font-size:1.6rem;letter-spacing:-.02em;margin-bottom:6px}
.ps{color:var(--muted);font-size:.875rem;margin-bottom:28px}
.cards-row{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px;margin-bottom:28px}
.card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:20px}
.card-label{font-size:.75rem;color:var(--muted);margin-bottom:8px;font-weight:500}
.card-value{font-family:'Syne',sans-serif;font-size:1.8rem;font-weight:800;letter-spacing:-.02em}
.card-value.blue{color:var(--blue2)}.card-value.green{color:var(--success)}
.form-group{margin-bottom:18px}
label{display:block;font-size:.8rem;font-weight:600;color:var(--muted);margin-bottom:7px;letter-spacing:.03em;text-transform:uppercase}
input,select{width:100%;background:rgba(255,255,255,.05);border:1px solid var(--border);border-radius:8px;padding:10px 14px;color:var(--white);font-size:.9rem;font-family:'DM Sans',sans-serif;transition:border .2s;outline:none}
input:focus,select:focus{border-color:var(--blue)}
input::placeholder{color:var(--muted)}
select option{background:#1a1f4e}
.btn{display:inline-flex;align-items:center;gap:8px;padding:10px 20px;border-radius:8px;font-family:'Syne',sans-serif;font-weight:700;font-size:.875rem;cursor:pointer;border:none;transition:all .2s}
.btn-primary{background:var(--blue);color:#fff;box-shadow:0 4px 16px rgba(50,92,254,.3)}
.btn-primary:hover{background:var(--blue2);transform:translateY(-1px)}
.btn-danger{background:rgba(239,68,68,.15);color:#ef4444;border:1px solid rgba(239,68,68,.3)}
.btn-danger:hover{background:rgba(239,68,68,.25)}
.btn-outline{background:transparent;color:var(--white);border:1px solid var(--border)}
.btn-outline:hover{background:var(--card)}
.btn-sm{padding:7px 14px;font-size:.8rem}
.tw{background:var(--card);border:1px solid var(--border);border-radius:12px;overflow:hidden}
table{width:100%;border-collapse:collapse}
th{padding:12px 16px;text-align:left;font-size:.75rem;font-weight:600;letter-spacing:.05em;text-transform:uppercase;color:var(--muted);border-bottom:1px solid var(--border)}
td{padding:12px 16px;font-size:.875rem;border-bottom:1px solid rgba(255,255,255,.04)}
tr:last-child td{border-bottom:none}
tr:hover td{background:rgba(255,255,255,.02)}
.badge{display:inline-flex;align-items:center;padding:3px 10px;border-radius:100px;font-size:.72rem;font-weight:600}
.bg{background:rgba(34,197,94,.15);color:#22c55e}.bb{background:rgba(50,92,254,.15);color:var(--blue2)}.br{background:rgba(239,68,68,.15);color:#ef4444}.bgr{background:rgba(255,255,255,.08);color:var(--muted)}
.alert{padding:12px 16px;border-radius:8px;font-size:.875rem;margin-bottom:16px;display:flex;align-items:center;gap:10px}
.as{background:rgba(34,197,94,.1);border:1px solid rgba(34,197,94,.3);color:#22c55e}
.ae{background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.3);color:#ef4444}
.ai{background:rgba(50,92,254,.1);border:1px solid rgba(50,92,254,.3);color:var(--blue2)}
.empty{text-align:center;padding:48px 20px;color:var(--muted)}
.empty-icon{font-size:2.5rem;margin-bottom:12px}
.empty-title{font-family:'Syne',sans-serif;font-weight:700;font-size:1rem;color:var(--white);margin-bottom:6px}
.empty-desc{font-size:.875rem;margin-bottom:20px}
.login-page{min-height:100vh;display:flex;align-items:center;justify-content:center;flex-direction:column;gap:32px;text-align:center;padding:20px}
.login-logo{display:flex;align-items:center;gap:14px;margin-bottom:8px}
.login-card{background:var(--card);border:1px solid var(--border);border-radius:16px;padding:36px;max-width:400px;width:100%}
.login-card h2{font-family:'Syne',sans-serif;font-weight:700;font-size:1.3rem;margin-bottom:8px}
.login-card p{color:var(--muted);font-size:.9rem;margin-bottom:24px;line-height:1.6}
.dbtn{display:flex;align-items:center;justify-content:center;gap:12px;background:#5865F2;color:#fff;padding:14px 24px;border-radius:10px;font-family:'Syne',sans-serif;font-weight:700;font-size:1rem;cursor:pointer;border:none;width:100%;transition:all .2s}
.dbtn:hover{background:#4752c4;transform:translateY(-1px)}
.server-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:14px;margin-top:20px}
.server-card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:20px;text-align:center;cursor:pointer;transition:all .25s}
.server-card:hover{border-color:var(--blue);background:rgba(50,92,254,.08);transform:translateY(-2px)}
.server-icon{width:52px;height:52px;border-radius:50%;margin:0 auto 12px;object-fit:cover;background:var(--blue);display:flex;align-items:center;justify-content:center;font-weight:800;font-size:1.1rem}
.server-name{font-size:.875rem;font-weight:600;word-break:break-word}
.verify-card{max-width:480px;margin:40px auto;background:var(--card);border:1px solid var(--border);border-radius:16px;padding:32px;text-align:center}
.verify-methods{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin:24px 0}
.method-btn{background:rgba(255,255,255,.04);border:1px solid var(--border);border-radius:10px;padding:18px 12px;cursor:pointer;transition:all .2s;color:var(--white);font-family:'DM Sans',sans-serif}
.method-btn:hover,.method-btn.active{border-color:var(--blue);background:rgba(50,92,254,.1)}
.method-icon{font-size:1.6rem;margin-bottom:8px}
.method-title{font-family:'Syne',sans-serif;font-weight:700;font-size:.9rem}
.method-desc{font-size:.75rem;color:var(--muted);margin-top:4px}
.code-box{background:rgba(0,0,0,.3);border:2px dashed rgba(50,92,254,.5);border-radius:10px;padding:20px;font-family:'Courier New',monospace;font-size:1.5rem;font-weight:700;color:var(--blue2);letter-spacing:.15em;margin:16px 0}
.sep{height:1px;background:var(--border);margin:20px 0}
.spinner{width:20px;height:20px;border:2px solid rgba(255,255,255,.2);border-top-color:#fff;border-radius:50%;animation:spin .7s linear infinite;display:inline-block}
@keyframes spin{to{transform:rotate(360deg)}}
@media(max-width:768px){.sidebar{display:none}.content{padding:20px 4%}.verify-methods{grid-template-columns:1fr}.cards-row{grid-template-columns:1fr 1fr}}
</style>
</head>
<body>
<div id="app"></div>
<script>
const API='/verificy/api';
let S={token:localStorage.getItem('vcy_token'),user:null,guilds:[],guild:null,page:'loading',groups:[],mappings:[]};
async function api(path,method='GET',body=null){
  const o={method,headers:{'Content-Type':'application/json'}};
  if(S.token)o.headers['Authorization']='Bearer '+S.token;
  if(body)o.body=JSON.stringify(body);
  const r=await fetch(API+path,o);
  if(r.status===401){logout();return null;}
  return r.json();
}
function go(p){S.page=p;render();}
function logout(){localStorage.removeItem('vcy_token');S.token=null;S.user=null;S.guild=null;go('login');}
async function init(){
  const p=new URLSearchParams(window.location.search);
  const t=p.get('token');
  if(t){localStorage.setItem('vcy_token',t);S.token=t;history.replaceState({},\`\`,location.pathname);}
  if(location.pathname.includes('/verified')){go('verified');return;}
  if(location.pathname.endsWith('/verify')){go('verify');return;}
  if(!S.token){go('login');return;}
  const me=await api('/auth/me');
  if(!me||me.error){go('login');return;}
  S.user=me;S.guilds=me.guilds||[];
  go(S.guilds.length?'servers':'login');
}
function logo(sz){return \`<svg width="\${sz}" height="\${sz}" viewBox="0 0 64 64" fill="none"><path d="M32 4L58 18V46L32 60L6 46V18L32 4Z" stroke="white" stroke-width="4" stroke-linejoin="round"/><path d="M20 32L28 40L44 24" stroke="white" stroke-width="5" stroke-linecap="round" stroke-linejoin="round"/></svg>\`;}
function topbar(){
  const u=S.user;
  const av=u?.avatar?\`<img class="avatar" src="https://cdn.discordapp.com/avatars/\${u.discord_id}/\${u.avatar}.png"/>\`:\`<div class="avatar-ph">\${u?.username?.slice(0,1)||'?'}</div>\`;
  return \`<div class="topbar"><div class="topbar-logo" onclick="go('servers')">\${logo(32)}<span class="logo-text">VerifiCy</span></div><div class="topbar-right">\${u?av:''}\${u?\`<span class="user-name">\${u.username}</span>\`:''}\${u?\`<button class="btn-logout" onclick="logout()">Sair</button>\`:''}</div></div>\`;
}
function sidebar(active){
  const items=[{id:'dashboard',icon:'📊',label:'Dashboard'},{id:'groups',icon:'🎮',label:'Grupos'},{id:'roles',icon:'🎭',label:'Cargos'},{id:'config',icon:'⚙️',label:'Configurações'},{id:'logs',icon:'📋',label:'Logs'}];
  return \`<div class="sidebar"><div class="sidebar-sep">SERVIDOR</div>\${items.map(i=>\`<div class="sidebar-item \${active===i.id?'active':''}" onclick="go('\${i.id}')"><span>\${i.icon}</span>\${i.label}</div>\`).join('')}<div style="flex:1"></div><div class="sidebar-item" onclick="go('servers')"><span>🔄</span>Trocar servidor</div></div>\`;
}
function layout(active,content){return topbar()+\`<div class="layout">\${sidebar(active)}<div class="content">\${content}</div></div>\`;}
function showAlert(id,type,msg){const el=document.getElementById(id);if(!el)return;const c={success:'as',error:'ae',info:'ai'}[type]||'ai';el.innerHTML=\`<div class="alert \${c}">\${msg}</div>\`;setTimeout(()=>{if(el)el.innerHTML='';},4000);}
function render(){
  const app=document.getElementById('app');
  switch(S.page){
    case 'loading':app.innerHTML=\`<div style="min-height:100vh;display:flex;align-items:center;justify-content:center"><div class="spinner" style="width:40px;height:40px;border-width:3px"></div></div>\`;break;
    case 'login':app.innerHTML=renderLogin();break;
    case 'servers':app.innerHTML=renderServers();break;
    case 'dashboard':app.innerHTML=layout('dashboard',renderDashboard());loadDashboard();break;
    case 'groups':app.innerHTML=layout('groups',renderGroups());loadGroups();break;
    case 'roles':app.innerHTML=layout('roles',renderRolesPage());loadRoles();break;
    case 'config':app.innerHTML=layout('config',renderConfig());loadConfig();break;
    case 'logs':app.innerHTML=layout('logs',renderLogsPage());loadLogs();break;
    case 'verify':app.innerHTML=renderVerify();break;
    case 'verified':app.innerHTML=renderVerifiedSuccess();break;
  }
}
function renderLogin(){return \`<div class="login-page"><div><div class="login-logo">\${logo(56)}<span style="font-family:'Syne',sans-serif;font-weight:800;font-size:2rem">VerifiCy</span></div><p style="color:var(--muted)">Verifique. Sincronize. Automatize.</p></div><div class="login-card"><h2>Entrar no Painel</h2><p>Faça login com sua conta Discord para gerenciar seus servidores.</p><button class="dbtn" onclick="loginDiscord()"><svg width="22" height="22" viewBox="0 0 24 24" fill="currentColor"><path d="M20.317 4.37a19.791 19.791 0 0 0-4.885-1.515.074.074 0 0 0-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 0 0-5.487 0 12.64 12.64 0 0 0-.617-1.25.077.077 0 0 0-.079-.037A19.736 19.736 0 0 0 3.677 4.37a.07.07 0 0 0-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 0 0 .031.057 19.9 19.9 0 0 0 5.993 3.03.078.078 0 0 0 .084-.028c.462-.63.874-1.295 1.226-1.994a.076.076 0 0 0-.041-.106 13.107 13.107 0 0 1-1.872-.892.077.077 0 0 1-.008-.128 10.2 10.2 0 0 0 .372-.292.074.074 0 0 1 .077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 0 1 .078.01c.12.098.246.198.373.292a.077.077 0 0 1-.006.127 12.299 12.299 0 0 1-1.873.892.077.077 0 0 0-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 0 0 .084.028 19.839 19.839 0 0 0 6.002-3.03.077.077 0 0 0 .032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 0 0-.031-.03z"/></svg>Entrar com Discord</button></div><p style="color:var(--muted);font-size:.75rem"><a href="/verificy/verify" style="color:var(--blue2)">Verificar minha conta Roblox</a></p></div>\`;}
function renderServers(){
  const g=S.guilds;
  return \`<div style="min-height:100vh;padding:40px 5%">\${topbar()}<div style="max-width:700px;margin:40px auto"><h1 class="pt">Selecionar Servidor</h1><p class="ps">Escolha o servidor Discord que deseja gerenciar.</p>\${!g.length?\`<div class="alert ai">Nenhum servidor onde você é admin. <a href="https://discord.com/oauth2/authorize?client_id=1513017992366264390&permissions=8&scope=bot+applications.commands" target="_blank" style="color:var(--blue2)">Adicionar VerifiCy →</a></div>\`:''}<div class="server-grid">\${g.map(x=>\`<div class="server-card" onclick="selectServer('\${x.id}','\${x.name.replace(/'/g,\\"\\\\'\\")}')"><div class="server-icon">\${x.icon?\`<img src="https://cdn.discordapp.com/icons/\${x.id}/\${x.icon}.png" style="width:100%;height:100%;border-radius:50%;object-fit:cover"/>\`:x.name.slice(0,2).toUpperCase()}</div><div class="server-name">\${x.name}</div></div>\`).join('')}<div class="server-card" onclick="window.open('https://discord.com/oauth2/authorize?client_id=1513017992366264390&permissions=8&scope=bot+applications.commands','_blank')" style="border-style:dashed;opacity:.7"><div class="server-icon" style="background:transparent;border:2px dashed var(--border);font-size:1.5rem">+</div><div class="server-name" style="color:var(--muted)">Adicionar servidor</div></div></div></div></div>\`;
}
function renderDashboard(){return \`<h1 class="pt">Dashboard</h1><p class="ps">Visão geral do servidor</p><div class="cards-row" id="dcards">\${[0,1,2,3].map(()=>'<div class="card"><div class="card-label">Carregando...</div><div class="card-value">—</div></div>').join('')}</div><div id="dlogs" class="tw"><table><thead><tr><th>Ação</th><th>Usuário</th><th>Data</th></tr></thead><tbody><tr><td colspan="3" style="text-align:center;padding:20px;color:var(--muted)">Carregando...</td></tr></tbody></table></div>\`;}
async function loadDashboard(){
  if(!S.guild)return;
  const d=await api('/dashboard/stats?guild_id='+S.guild.id);
  if(!d)return;
  const c=document.getElementById('dcards');
  if(c)c.innerHTML=[{l:'Verificados',v:d.total_verified||0,cl:'blue'},{l:'Servidores',v:d.total_servers||0,cl:''},{l:'Grupos',v:d.total_groups||0,cl:''},{l:'Hoje',v:d.verified_today||0,cl:'green'}].map(x=>\`<div class="card"><div class="card-label">\${x.l}</div><div class="card-value \${x.cl}">\${x.v}</div></div>\`).join('');
  const ld=await api('/logs?guild_id='+S.guild.id);
  const le=document.getElementById('dlogs');
  if(le&&ld?.logs){const rows=ld.logs.slice(0,10).map(l=>\`<tr><td><span class="badge bb">\${l.action}</span></td><td>\${l.discord_id||'—'}</td><td style="color:var(--muted);font-size:.8rem">\${new Date(l.created_at).toLocaleString('pt-BR')}</td></tr>\`).join('')||'<tr><td colspan="3" style="text-align:center;padding:20px;color:var(--muted)">Nenhum log ainda</td></tr>';le.innerHTML=\`<table><thead><tr><th>Ação</th><th>Usuário</th><th>Data</th></tr></thead><tbody>\${rows}</tbody></table>\`;}
}
function renderGroups(){return \`<h1 class="pt">Grupos Roblox</h1><p class="ps">Conecte grupos Roblox ao seu servidor</p><div id="ga"></div><div style="display:flex;gap:10px;margin-bottom:20px"><input id="gi" type="text" placeholder="ID ou link do grupo" style="max-width:340px"/><button class="btn btn-primary" onclick="addGroup()">+ Adicionar</button></div><div id="gl"></div>\`;}
async function loadGroups(){
  if(!S.guild)return;
  const d=await api('/groups?guild_id='+S.guild.id);
  if(!d)return;
  S.groups=d.groups||[];
  const el=document.getElementById('gl');
  if(!el)return;
  if(!S.groups.length){el.innerHTML='<div class="empty"><div class="empty-icon">🎮</div><div class="empty-title">Nenhum grupo</div><div class="empty-desc">Adicione um grupo Roblox para começar.</div></div>';return;}
  el.innerHTML=\`<div class="tw"><table><thead><tr><th>Nome</th><th>ID</th><th></th></tr></thead><tbody>\${S.groups.map(g=>\`<tr><td><strong>\${g.group_name||g.group_id}</strong></td><td><code>\${g.group_id}</code></td><td><button class="btn btn-danger btn-sm" onclick="removeGroup('\${g.group_id}')">Remover</button></td></tr>\`).join('')}</tbody></table></div>\`;
}
async function addGroup(){
  const inp=document.getElementById('gi');
  let id=inp?.value?.trim();if(!id)return;
  const m=id.match(/groups\/([0-9]+)/);if(m)id=m[1];
  showAlert('ga','info','Buscando grupo...');
  const d=await api('/groups?guild_id='+S.guild.id,'POST',{group_id:id});
  if(d?.success){showAlert('ga','success',\`Grupo "\${d.group.name}" adicionado!\`);inp.value='';await loadGroups();}
  else showAlert('ga','error',d?.error||'Erro ao adicionar grupo');
}
async function removeGroup(id){if(!confirm('Remover este grupo?'))return;await api('/groups?guild_id='+S.guild.id,'DELETE',{group_id:id});await loadGroups();}
function renderRolesPage(){return \`<h1 class="pt">Mapeamento de Cargos</h1><p class="ps">Vincule ranks Roblox a cargos Discord</p><div id="ra"></div><div style="background:var(--card);border:1px solid var(--border);border-radius:12px;padding:20px;margin-bottom:20px"><div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;margin-bottom:14px"><div class="form-group" style="margin:0"><label>Grupo</label><select id="rg" onchange="loadRanks()"><option value="">Selecione...</option></select></div><div class="form-group" style="margin:0"><label>Rank Roblox</label><select id="rr"><option>Selecione o grupo primeiro</option></select></div><div class="form-group" style="margin:0"><label>ID Cargo Discord</label><input id="rd" type="text" placeholder="ID do cargo"/></div></div><div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:14px"><div class="form-group" style="margin:0"><label>Tipo Prefixo</label><select id="pt"><option value="auto">Automático</option><option value="manual">Manual</option><option value="none">Sem prefixo</option></select></div><div class="form-group" style="margin:0"><label>Prefixo Manual</label><input id="pv" type="text" placeholder="Ex: [MOD]"/></div></div><button class="btn btn-primary" onclick="addMapping()">+ Adicionar mapeamento</button></div><div id="ml"></div>\`;}
async function loadRoles(){
  if(!S.guild)return;
  const d=await api('/roles?guild_id='+S.guild.id);
  if(d)S.mappings=d.mappings||[];
  renderMappingsList();
  const sel=document.getElementById('rg');
  if(sel&&S.groups.length){S.groups.forEach(g=>{const o=document.createElement('option');o.value=g.group_id;o.textContent=g.group_name||g.group_id;sel.appendChild(o);});}
}
async function loadRanks(){
  const gid=document.getElementById('rg')?.value;
  const rs=document.getElementById('rr');
  if(!gid||!rs)return;
  rs.innerHTML='<option>Carregando...</option>';
  const d=await api('/groups/ranks?guild_id='+S.guild.id+'&group_id='+gid);
  if(d?.ranks)rs.innerHTML='<option value="">Selecione...</option>'+d.ranks.map(r=>\`<option value="\${r.rank}" data-name="\${r.name}">\${r.name} (Rank \${r.rank})</option>\`).join('');
}
function renderMappingsList(){
  const el=document.getElementById('ml');if(!el)return;
  if(!S.mappings.length){el.innerHTML='<div class="empty"><div class="empty-icon">🎭</div><div class="empty-title">Nenhum mapeamento</div><div class="empty-desc">Adicione acima para vincular ranks a cargos.</div></div>';return;}
  el.innerHTML=\`<div class="tw"><table><thead><tr><th>Grupo</th><th>Rank</th><th>Cargo Discord</th><th>Prefixo</th><th></th></tr></thead><tbody>\${S.mappings.map(m=>\`<tr><td>\${m.group_id}</td><td>\${m.roblox_rank_name||m.roblox_rank_id}</td><td><code>\${m.discord_role_id}</code></td><td>\${m.prefix?\`<span class="badge bb">\${m.prefix}</span>\`:'<span class="badge bgr">—</span>'}</td><td><button class="btn btn-danger btn-sm" onclick="removeMapping('\${m.group_id}','\${m.roblox_rank_id}')">✕</button></td></tr>\`).join('')}</tbody></table></div>\`;
}
async function addMapping(){
  const gid=document.getElementById('rg')?.value;
  const rs=document.getElementById('rr');
  const rv=rs?.value,rn=rs?.options[rs?.selectedIndex]?.dataset?.name;
  const did=document.getElementById('rd')?.value?.trim();
  const pt=document.getElementById('pt')?.value;
  const pv=document.getElementById('pv')?.value?.trim();
  if(!gid||!rv||!did)return showAlert('ra','error','Preencha todos os campos');
  const d=await api('/roles?guild_id='+S.guild.id,'POST',{group_id:gid,roblox_rank_id:rv,roblox_rank_name:rn,discord_role_id:did,prefix_type:pt,prefix:pv});
  if(d?.success){showAlert('ra','success','Mapeamento adicionado!');await loadRoles();}
  else showAlert('ra','error',d?.error||'Erro');
}
async function removeMapping(gid,rid){await api('/roles?guild_id='+S.guild.id,'DELETE',{group_id:gid,roblox_rank_id:rid});await loadRoles();}
function renderConfig(){return \`<h1 class="pt">Configurações</h1><p class="ps">Configurações do servidor</p><div id="ca"></div><div style="max-width:520px"><div class="form-group"><label>ID do Cargo "Verificado"</label><input id="vri" type="text" placeholder="ID do cargo Discord"/><p style="color:var(--muted);font-size:.75rem;margin-top:6px">Dado a todos após verificação. Nunca removido automaticamente.</p></div><div class="form-group"><label>Formato do Nickname</label><select id="nf"><option value="{username}">Username: Ruano_BR</option><option value="{display}">Display Name: Ruano</option><option value="{prefix} {username}">Prefixo + Username: [MOD] Ruano_BR</option><option value="{prefix} {display}">Prefixo + Display: [MOD] Ruano</option></select></div><button class="btn btn-primary" onclick="saveConfig()">💾 Salvar</button><div class="sep"></div><h3 style="font-family:'Syne',sans-serif;font-weight:700;margin-bottom:12px">Sincronização Global</h3><p style="color:var(--muted);font-size:.875rem;margin-bottom:14px">Ressincroniza todos os membros verificados do servidor.</p><button class="btn btn-outline" onclick="syncAll()">🔄 Ressincronizar todos</button></div>\`;}
async function loadConfig(){
  if(!S.guild)return;
  const d=await api('/dashboard/server?guild_id='+S.guild.id);
  if(d?.server){const s=d.server;const r=document.getElementById('vri');const n=document.getElementById('nf');if(r)r.value=s.verified_role_id||'';if(n)n.value=s.nickname_format||'{username}';}
}
async function saveConfig(){
  const d=await api('/dashboard/server?guild_id='+S.guild.id,'PUT',{verified_role_id:document.getElementById('vri')?.value?.trim(),nickname_format:document.getElementById('nf')?.value});
  if(d?.success)showAlert('ca','success','Configurações salvas!');else showAlert('ca','error','Erro ao salvar');
}
async function syncAll(){
  if(!confirm('Ressincronizar TODOS os membros?'))return;
  showAlert('ca','info','Enviando para fila...');
  const d=await api('/sync/server','POST',{guild_id:S.guild.id});
  if(d?.success)showAlert('ca','success',d.message);else showAlert('ca','error','Erro');
}
function renderLogsPage(){return \`<h1 class="pt">Logs</h1><p class="ps">Histórico de ações</p><div id="lt"><div style="text-align:center;padding:40px;color:var(--muted)">Carregando...</div></div>\`;}
async function loadLogs(){
  if(!S.guild)return;
  const d=await api('/logs?guild_id='+S.guild.id);
  const el=document.getElementById('lt');if(!el)return;
  if(!d?.logs?.length){el.innerHTML='<div class="empty"><div class="empty-icon">📋</div><div class="empty-title">Nenhum log</div><div class="empty-desc">Ações aparecerão aqui.</div></div>';return;}
  el.innerHTML=\`<div class="tw"><table><thead><tr><th>Ação</th><th>Usuário</th><th>Detalhes</th><th>Data</th></tr></thead><tbody>\${d.logs.map(l=>{const c=l.action.includes('SYNC')?'bb':l.action.includes('ERROR')?'br':'bgr';return \`<tr><td><span class="badge \${c}">\${l.action}</span></td><td>\${l.discord_id||'—'}</td><td style="color:var(--muted);font-size:.8rem">\${l.details?JSON.stringify(JSON.parse(l.details)).slice(0,60):'—'}</td><td style="color:var(--muted);font-size:.8rem">\${new Date(l.created_at).toLocaleString('pt-BR')}</td></tr>\`;}).join('')}</tbody></table></div>\`;
}
function renderVerify(){return \`<div style="min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:20px">\${logo(40)}<div class="verify-card" style="margin-top:20px"><h2 style="font-family:'Syne',sans-serif;font-weight:800;font-size:1.4rem;margin-bottom:8px">Verificar conta Roblox</h2><p style="color:var(--muted);font-size:.875rem;margin-bottom:4px">Escolha como deseja se verificar:</p><div class="verify-methods"><div class="method-btn active" onclick="selMethod('oauth',this)"><div class="method-icon">🔗</div><div class="method-title">OAuth</div><div class="method-desc">Login direto</div></div><div class="method-btn" onclick="selMethod('bio',this)"><div class="method-icon">📝</div><div class="method-title">Bio</div><div class="method-desc">Código na bio</div></div></div><div id="vc"><button class="btn btn-primary" style="width:100%" onclick="startOAuth()">Entrar com Roblox</button></div></div></div>\`;}
function selMethod(m,el){document.querySelectorAll('.method-btn').forEach(b=>b.classList.remove('active'));el.classList.add('active');const c=document.getElementById('vc');if(!c)return;if(m==='oauth'){c.innerHTML='<button class="btn btn-primary" style="width:100%" onclick="startOAuth()">Entrar com Roblox</button>';}else{c.innerHTML=\`<div id="bs1"><input type="text" id="ru" placeholder="Username no Roblox" style="margin-bottom:12px"/><button class="btn btn-primary" style="width:100%" onclick="genBioCode()">Gerar código</button></div><div id="bs2" style="display:none"><p style="font-size:.875rem;color:var(--muted);margin-bottom:8px">Cole este código na sua Bio do Roblox:</p><div class="code-box" id="bcd">—</div><p style="font-size:.8rem;color:var(--muted);margin-bottom:14px">Acesse <a href="https://www.roblox.com/users/profile" target="_blank" style="color:var(--blue2)">roblox.com/users/profile</a> e cole na bio.</p><button class="btn btn-primary" style="width:100%;margin-bottom:8px" onclick="checkBio()">✓ Já coloquei o código</button><div id="bal"></div></div>\`;}}
async function startOAuth(){if(!S.token){go('login');return;}const d=await api('/verify/roblox/start');if(d?.url)location.href=d.url;}
async function genBioCode(){if(!S.token){go('login');return;}const d=await api('/verify/bio/generate','POST',{});if(d?.code){document.getElementById('bs1').style.display='none';document.getElementById('bs2').style.display='block';document.getElementById('bcd').textContent=d.code;}}
async function checkBio(){const u=document.getElementById('ru')?.value?.trim();if(!u){showAlert('bal','error','Digite seu username Roblox');return;}showAlert('bal','info','Verificando...');const d=await api('/verify/bio/check','POST',{roblox_username:u});if(d?.success)location.href='/verificy/verified?success=true';else showAlert('bal','error',d?.error||'Código não encontrado na bio');}
function renderVerifiedSuccess(){const s=new URLSearchParams(location.search).get('success'),e=new URLSearchParams(location.search).get('error');return \`<div style="min-height:100vh;display:flex;align-items:center;justify-content:center;text-align:center;padding:20px;flex-direction:column;gap:16px">\${s?\`<div style="font-size:3rem">✅</div><h2 style="font-family:'Syne',sans-serif;font-weight:800;font-size:1.5rem">Verificado com sucesso!</h2><p style="color:var(--muted)">Conta Roblox vinculada. Seus cargos serão aplicados em instantes.</p><button class="btn btn-primary" onclick="go('dashboard')">Ir para o painel</button>\`:\`<div style="font-size:3rem">❌</div><h2 style="font-family:'Syne',sans-serif;font-weight:800;font-size:1.5rem">Erro na verificação</h2><p style="color:var(--muted)">\${e||'Tente novamente.'}</p><button class="btn btn-outline" onclick="go('verify')">Tentar novamente</button>\`}</div>\`;}
async function selectServer(id,name){await api('/auth/select-server','POST',{guild_id:id});S.guild={id,name};go('dashboard');}
function loginDiscord(){location.href=API+'/auth/discord/login';}
window.go=go;window.logout=logout;window.loginDiscord=loginDiscord;window.selectServer=selectServer;
window.addGroup=addGroup;window.removeGroup=removeGroup;window.loadRanks=loadRanks;
window.addMapping=addMapping;window.removeMapping=removeMapping;
window.saveConfig=saveConfig;window.syncAll=syncAll;
window.selMethod=selMethod;window.startOAuth=startOAuth;window.genBioCode=genBioCode;window.checkBio=checkBio;
init();
</script>
</body>
</html>`, { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
}
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname.replace('/verificy', '') || '/';
    const method = request.method;
    if (method === 'OPTIONS') return new Response(null, { headers: corsHeaders(env) });
    try {
      if (path.startsWith('/api/auth/'))      return handleAuth(path, method, request, env);
      if (path.startsWith('/api/verify/'))    return handleVerify(path, method, request, env);
      if (path.startsWith('/api/sync/'))      return handleSync(path, method, request, env);
      if (path.startsWith('/api/groups'))     return handleGroups(path, method, request, env);
      if (path.startsWith('/api/roles'))      return handleRoles(path, method, request, env);
      if (path.startsWith('/api/dashboard'))  return handleDashboard(path, method, request, env);
      if (path.startsWith('/api/logs'))       return handleLogs(path, method, request, env);
      if (path.startsWith('/api/bot/'))       return handleBotRoutes(path, method, request, env);
      return serveHTML();
    } catch (err) {
      console.error('Worker error:', err);
      return errorResponse(500, 'Erro interno do servidor', env);
    }
  }
};
