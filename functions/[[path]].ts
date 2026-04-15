interface Env {
    ok: true,
    item: cert,
    files: {
      cert: certPem ? await certPem.text() : null,
      chain: chainPem ? await chainPem.text() : null,
      fullchain: fullchainPem ? await fullchainPem.text() : null,
      privkey: privkeyPem ? await privkeyPem.text() : null,
      pubkey: pubkeyPem ? await pubkeyPem.text() : null,
    }
  });
}

async function runRenewCheck(env: Env) {
  const rs = await env.DB.prepare(`
    SELECT * FROM domains
    WHERE auto_renew = 1 AND expires_at IS NOT NULL
  `).all();

  const items = (rs.results || []) as any[];
  const now = Date.now();
  const due: any[] = [];

  for (const item of items) {
    const exp = new Date(item.expires_at).getTime();
    const daysLeft = Math.floor((exp - now) / 86400000);
    if (daysLeft <= 30) due.push({ ...item, daysLeft });
  }

  for (const item of due) {
    await env.DB.prepare(`
      INSERT INTO renew_logs (domain_id, action, success, message)
      VALUES (?, 'renew-check', 1, ?)
    `).bind(item.id, `待续签，剩余 ${item.daysLeft} 天`).run();
  }

  return { ok: true, dueCount: due.length, due };
}

export async function onRequest(context: any) {
  const { request, env, params } = context;
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method.toUpperCase();

  if (method === 'OPTIONS') return new Response(null, { status: 204 });

  try {
    if (path === '/api/domains' && method === 'GET') return listDomains(env);
    if (path === '/api/domains' && method === 'POST') return createDomain(env, request);

    const m1 = path.match(/^\/api\/domains\/(\d+)$/);
    if (m1 && method === 'GET') return getDomain(env, m1[1]);

    const m2 = path.match(/^\/api\/domains\/(\d+)\/issue$/);
    if (m2 && method === 'POST') return startIssue(env, m2[1]);

    const m3 = path.match(/^\/api\/domains\/(\d+)\/finalize$/);
    if (m3 && method === 'POST') return finalizeIssue(env, m3[1]);

    const m4 = path.match(/^\/api\/domains\/(\d+)\/cert$/);
    if (m4 && method === 'GET') return getLatestCert(env, m4[1]);

    const m5 = path.match(/^\/api\/admin\/renew-check$/);
    if (m5 && method === 'POST') {
      const result = await runRenewCheck(env);
      return json(result);
    }

    return json({ ok: false, error: 'Not Found' }, 404);
  } catch (e: any) {
    return json({ ok: false, error: e?.message || '服务器错误' }, 500);
  }
}

export async function onScheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext) {
  ctx.waitUntil(runRenewCheck(env).then((result) => {
    console.log('renew-check:', JSON.stringify(result));
  }));
}
