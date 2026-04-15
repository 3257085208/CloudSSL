export interface Env {
  DB: D1Database;
  CERTS: R2Bucket;
  APP_NAME: string;
}

type JsonMap = Record<string, unknown>;

function json(data: JsonMap, status = 200): Response {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8"
    }
  });
}

async function parseBody(request: Request): Promise<any> {
  try {
    return await request.json();
  } catch {
    return {};
  }
}

async function listDomains(env: Env): Promise<Response> {
  const rs = await env.DB.prepare(
    `SELECT * FROM domains ORDER BY id DESC`
  ).all();

  const items = (rs.results || []).map((x: any) => ({
    ...x,
    auto_renew: !!x.auto_renew,
    disable_cname: !!x.disable_cname,
    skip_dns_precheck: !!x.skip_dns_precheck
  }));

  return json({ ok: true, items });
}

async function createDomain(env: Env, request: Request): Promise<Response> {
  const body = await parseBody(request);

  if (!body.domain) {
    return json({ ok: false, error: "domain 不能为空" }, 400);
  }

  const sans = JSON.stringify(body.sans || []);
  const dnsApiTokenEncrypted =
    typeof body.dns_api_token === "string" ? body.dns_api_token : "";

  await env.DB.prepare(`
    INSERT INTO domains (
      domain,
      sans_json,
      acme_directory,
      acme_account_name,
      account_key_algorithm,
      cert_key_algorithm,
      auto_renew,
      disable_cname,
      skip_dns_precheck,
      dns_server_1,
      dns_server_2,
      validation_mode,
      dns_provider,
      dns_api_token_encrypted,
      status,
      updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'draft', CURRENT_TIMESTAMP)
  `).bind(
    body.domain,
    sans,
    body.acme_directory || "https://acme-v02.api.letsencrypt.org/directory",
    body.acme_account_name || "default",
    body.account_key_algorithm || "ecdsa-p256",
    body.cert_key_algorithm || "ecdsa-p256",
    body.auto_renew ? 1 : 0,
    body.disable_cname ? 1 : 0,
    body.skip_dns_precheck ? 1 : 0,
    body.dns_server_1 || "",
    body.dns_server_2 || "",
    body.validation_mode || "manual",
    body.dns_provider || "",
    dnsApiTokenEncrypted
  ).run();

  return json({ ok: true });
}

async function getDomain(env: Env, id: string): Promise<Response> {
  const row = await env.DB.prepare(
    `SELECT * FROM domains WHERE id = ?`
  ).bind(id).first();

  if (!row) {
    return json({ ok: false, error: "域名不存在" }, 404);
  }

  return json({ ok: true, item: row as unknown as JsonMap });
}

function fakeDnsToken(domain: string): string {
  return `fake_dns_token_${domain.replace(/\./g, "_")}`;
}

async function startIssue(env: Env, id: string): Promise<Response> {
  const row: any = await env.DB.prepare(
    `SELECT * FROM domains WHERE id = ?`
  ).bind(id).first();

  if (!row) {
    return json({ ok: false, error: "域名不存在" }, 404);
  }

  const txtName = `_acme-challenge.${row.domain}`;
  const txtValue = fakeDnsToken(row.domain);

  await env.DB.prepare(`
    UPDATE domains
    SET status = 'pending_dns',
        updated_at = CURRENT_TIMESTAMP,
        last_error = ''
    WHERE id = ?
  `).bind(id).run();

  return json({
    ok: true,
    step: "pending_dns",
    message:
      row.validation_mode === "manual"
        ? "请先手动添加 TXT 记录，然后点击继续验证。"
        : "这里后续可接 DNS API 自动写入 TXT。当前先返回需要写入的记录。",
    dns_record: {
      type: "TXT",
      name: txtName,
      value: txtValue
    }
  });
}

async function finalizeIssue(env: Env, id: string): Promise<Response> {
  const row: any = await env.DB.prepare(
    `SELECT * FROM domains WHERE id = ?`
  ).bind(id).first();

  if (!row) {
    return json({ ok: false, error: "域名不存在" }, 404);
  }

  const now = new Date();
  const after = new Date(now.getTime() + 90 * 24 * 60 * 60 * 1000);

  const base = `certs/${row.domain}/${Date.now()}`;
  const certPem = `-----BEGIN CERTIFICATE-----
FAKE_CERT_FOR_${row.domain}
-----END CERTIFICATE-----`;

  const chainPem = `-----BEGIN CERTIFICATE-----
FAKE_CHAIN
-----END CERTIFICATE-----`;

  const fullchainPem = `${certPem}
${chainPem}`;

  const privkeyPem = `-----BEGIN PRIVATE KEY-----
FAKE_PRIVATE_KEY
-----END PRIVATE KEY-----`;

  const pubkeyPem = `-----BEGIN PUBLIC KEY-----
FAKE_PUBLIC_KEY
-----END PUBLIC KEY-----`;

  await env.CERTS.put(`${base}/cert.pem`, certPem);
  await env.CERTS.put(`${base}/chain.pem`, chainPem);
  await env.CERTS.put(`${base}/fullchain.pem`, fullchainPem);
  await env.CERTS.put(`${base}/privkey.pem`, privkeyPem);
  await env.CERTS.put(`${base}/pubkey.pem`, pubkeyPem);

  await env.DB.prepare(`
    INSERT INTO certificates (
      domain_id,
      cert_path,
      chain_path,
      fullchain_path,
      privkey_path,
      pubkey_path,
      serial_number,
      not_before,
      not_after
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(
    id,
    `${base}/cert.pem`,
    `${base}/chain.pem`,
    `${base}/fullchain.pem`,
    `${base}/privkey.pem`,
    `${base}/pubkey.pem`,
    `FAKE-${Date.now()}`,
    now.toISOString(),
    after.toISOString()
  ).run();

  await env.DB.prepare(`
    UPDATE domains
    SET status = 'issued',
        expires_at = ?,
        updated_at = CURRENT_TIMESTAMP
    WHERE id = ?
  `).bind(after.toISOString(), id).run();

  await env.DB.prepare(`
    INSERT INTO renew_logs (domain_id, action, success, message)
    VALUES (?, 'issue', 1, 'issued by placeholder flow')
  `).bind(id).run();

  return json({
    ok: true,
    step: "issued",
    message: "示例版已生成占位证书并写入 R2。",
    expires_at: after.toISOString()
  });
}

async function getLatestCert(env: Env, id: string): Promise<Response> {
  const cert: any = await env.DB.prepare(`
    SELECT * FROM certificates
    WHERE domain_id = ?
    ORDER BY id DESC
    LIMIT 1
  `).bind(id).first();

  if (!cert) {
    return json({ ok: false, error: "还没有证书" }, 404);
  }

  const certObj = await env.CERTS.get(cert.cert_path);
  const chainObj = await env.CERTS.get(cert.chain_path);
  const fullchainObj = await env.CERTS.get(cert.fullchain_path);
  const privkeyObj = await env.CERTS.get(cert.privkey_path);
  const pubkeyObj = await env.CERTS.get(cert.pubkey_path);

  const certText = certObj ? await certObj.text() : null;
  const chainText = chainObj ? await chainObj.text() : null;
  const fullchainText = fullchainObj ? await fullchainObj.text() : null;
  const privkeyText = privkeyObj ? await privkeyObj.text() : null;
  const pubkeyText = pubkeyObj ? await pubkeyObj.text() : null;

  return json({
    ok: true,
    item: cert,
    files: {
      cert: certText,
      chain: chainText,
      fullchain: fullchainText,
      privkey: privkeyText,
      pubkey: pubkeyText
    }
  });
}

async function runRenewCheck(env: Env): Promise<Response> {
  const rs = await env.DB.prepare(`
    SELECT * FROM domains
    WHERE auto_renew = 1
      AND expires_at IS NOT NULL
    ORDER BY id DESC
  `).all();

  const items = (rs.results || []) as any[];
  const now = Date.now();
  const due: any[] = [];

  for (const item of items) {
    const exp = new Date(item.expires_at).getTime();
    const daysLeft = Math.floor((exp - now) / 86400000);
    if (daysLeft <= 30) {
      due.push({
        id: item.id,
        domain: item.domain,
        daysLeft
      });

      await env.DB.prepare(`
        INSERT INTO renew_logs (domain_id, action, success, message)
        VALUES (?, 'renew-check', 1, ?)
      `).bind(item.id, `待续签，剩余 ${daysLeft} 天`).run();
    }
  }

  return json({
    ok: true,
    dueCount: due.length,
    due
  });
}

export const onRequest: PagesFunction<Env> = async (context) => {
  const { request, env } = context;
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method.toUpperCase();

  if (method === "OPTIONS") {
    return new Response(null, { status: 204 });
  }

  try {
    if (path === "/api/domains" && method === "GET") {
      return await listDomains(env);
    }

    if (path === "/api/domains" && method === "POST") {
      return await createDomain(env, request);
    }

    const domainMatch = path.match(/^\/api\/domains\/(\d+)$/);
    if (domainMatch && method === "GET") {
      return await getDomain(env, domainMatch[1]);
    }

    const issueMatch = path.match(/^\/api\/domains\/(\d+)\/issue$/);
    if (issueMatch && method === "POST") {
      return await startIssue(env, issueMatch[1]);
    }

    const finalizeMatch = path.match(/^\/api\/domains\/(\d+)\/finalize$/);
    if (finalizeMatch && method === "POST") {
      return await finalizeIssue(env, finalizeMatch[1]);
    }

    const certMatch = path.match(/^\/api\/domains\/(\d+)\/cert$/);
    if (certMatch && method === "GET") {
      return await getLatestCert(env, certMatch[1]);
    }

    if (path === "/api/admin/renew-check" && method === "POST") {
      return await runRenewCheck(env);
    }

    return json({ ok: false, error: "Not Found" }, 404);
  } catch (error) {
    const message =
      error instanceof Error ? error.message : "服务器内部错误";
    return json({ ok: false, error: message }, 500);
  }
};
