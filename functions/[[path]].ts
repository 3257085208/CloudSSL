export interface Env {
  DB: D1Database;
  CERTS: R2Bucket;
  APP_NAME: string;
}

type JsonMap = Record<string, unknown>;

type StoredAccount = {
  alg: string;
  directory: string;
  kid?: string;
  privateJwk: JsonWebKey;
  publicJwk: JsonWebKey;
};

type AcmeDirectory = {
  newNonce: string;
  newAccount: string;
  newOrder: string;
  revokeCert?: string;
  keyChange?: string;
};

type PendingChallenge = {
  identifier: string;
  authzUrl: string;
  challengeUrl: string;
  txtName: string;
  txtValue: string;
};

type PendingState = {
  domainId: number;
  domain: string;
  identifiers: string[];
  orderUrl: string;
  finalizeUrl: string;
  accountName: string;
  directoryUrl: string;
  accountAlg: string;
  certAlg: string;
  challenges: PendingChallenge[];
  createdAt: string;
};

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

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

function utf8(input: string): Uint8Array {
  return textEncoder.encode(input);
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

function bytesToBase64(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

function base64ToBytes(base64: string): Uint8Array {
  const normalized = base64.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4 || 4)) % 4);
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function base64UrlEncode(bytes: Uint8Array): string {
  return bytesToBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlEncodeString(value: string): string {
  return base64UrlEncode(utf8(value));
}

function pemToDer(pem: string): Uint8Array {
  const body = pem.replace(/-----BEGIN [^-]+-----/g, "")
    .replace(/-----END [^-]+-----/g, "")
    .replace(/\s+/g, "");
  return base64ToBytes(body);
}

function derToPem(label: string, der: Uint8Array): string {
  const b64 = bytesToBase64(der);
  const lines = b64.match(/.{1,64}/g) || [];
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----`;
}

function asn1Len(len: number): Uint8Array {
  if (len < 128) return Uint8Array.of(len);
  const bytes: number[] = [];
  let n = len;
  while (n > 0) {
    bytes.unshift(n & 0xff);
    n >>= 8;
  }
  return Uint8Array.of(0x80 | bytes.length, ...bytes);
}

function asn1(tag: number, ...contents: Uint8Array[]): Uint8Array {
  const content = concatBytes(...contents);
  return concatBytes(Uint8Array.of(tag), asn1Len(content.length), content);
}

function asn1Seq(...contents: Uint8Array[]): Uint8Array {
  return asn1(0x30, ...contents);
}

function asn1Set(...contents: Uint8Array[]): Uint8Array {
  return asn1(0x31, ...contents);
}

function asn1Int(n: number): Uint8Array {
  if (n === 0) return asn1(0x02, Uint8Array.of(0x00));
  const bytes: number[] = [];
  let x = n;
  while (x > 0) {
    bytes.unshift(x & 0xff);
    x >>= 8;
  }
  if (bytes[0] & 0x80) bytes.unshift(0);
  return asn1(0x02, Uint8Array.from(bytes));
}

function asn1Utf8(str: string): Uint8Array {
  return asn1(0x0c, utf8(str));
}

function asn1Ia5(str: string): Uint8Array {
  return asn1(0x16, utf8(str));
}

function asn1Null(): Uint8Array {
  return asn1(0x05, new Uint8Array());
}

function encodeOid(oid: string): Uint8Array {
  const parts = oid.split(".").map((x) => parseInt(x, 10));
  const first = 40 * parts[0] + parts[1];
  const out = [first];
  for (let i = 2; i < parts.length; i++) {
    let value = parts[i];
    const stack = [value & 0x7f];
    value >>= 7;
    while (value > 0) {
      stack.unshift((value & 0x7f) | 0x80);
      value >>= 7;
    }
    out.push(...stack);
  }
  return asn1(0x06, Uint8Array.from(out));
}

function asn1BitString(raw: Uint8Array): Uint8Array {
  return asn1(0x03, Uint8Array.of(0x00), raw);
}

function asn1OctetString(raw: Uint8Array): Uint8Array {
  return asn1(0x04, raw);
}

function asn1Ctx(tagNum: number, raw: Uint8Array): Uint8Array {
  return asn1(0xa0 + tagNum, raw);
}

function asn1ImplicitCtx(tagNum: number, raw: Uint8Array): Uint8Array {
  return asn1(0x80 + tagNum, raw);
}

function normalizeDomain(domain: string): string {
  return domain.trim().toLowerCase().replace(/\.$/, "");
}

function splitPemChain(pem: string): string[] {
  return pem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) || [];
}

function stateKey(domainId: number): string {
  return `acme-state/${domainId}.json`;
}

function accountKey(name: string): string {
  return `acme-accounts/${name}.json`;
}

function safeJsonParse<T>(text: string): T {
  return JSON.parse(text) as T;
}

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const hash = await crypto.subtle.digest("SHA-256", data);
  return new Uint8Array(hash);
}

function getAccountSigningSpec(alg: string) {
  switch (alg) {
    case "rsa-2048":
      return {
        jwkAlg: "RS256",
        keyGen: {
          name: "RSASSA-PKCS1-v1_5",
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: "SHA-256"
        } as RsaHashedKeyGenParams,
        importAlgo: {
          name: "RSASSA-PKCS1-v1_5",
          hash: "SHA-256"
        } as RsaHashedImportParams,
        signAlgo: { name: "RSASSA-PKCS1-v1_5" } as AlgorithmIdentifier,
        sigType: "rsa" as const
      };
    case "rsa-4096":
      return {
        jwkAlg: "RS256",
        keyGen: {
          name: "RSASSA-PKCS1-v1_5",
          modulusLength: 4096,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: "SHA-256"
        } as RsaHashedKeyGenParams,
        importAlgo: {
          name: "RSASSA-PKCS1-v1_5",
          hash: "SHA-256"
        } as RsaHashedImportParams,
        signAlgo: { name: "RSASSA-PKCS1-v1_5" } as AlgorithmIdentifier,
        sigType: "rsa" as const
      };
    case "ecdsa-p384":
      return {
        jwkAlg: "ES384",
        keyGen: {
          name: "ECDSA",
          namedCurve: "P-384"
        } as EcKeyGenParams,
        importAlgo: {
          name: "ECDSA",
          namedCurve: "P-384"
        } as EcKeyImportParams,
        signAlgo: {
          name: "ECDSA",
          hash: "SHA-384"
        } as EcdsaParams,
        sigType: "ecdsa" as const,
        joseSize: 96
      };
    case "ecdsa-p256":
    default:
      return {
        jwkAlg: "ES256",
        keyGen: {
          name: "ECDSA",
          namedCurve: "P-256"
        } as EcKeyGenParams,
        importAlgo: {
          name: "ECDSA",
          namedCurve: "P-256"
        } as EcKeyImportParams,
        signAlgo: {
          name: "ECDSA",
          hash: "SHA-256"
        } as EcdsaParams,
        sigType: "ecdsa" as const,
        joseSize: 64
      };
  }
}

function getCertSigningSpec(alg: string) {
  switch (alg) {
    case "rsa-2048":
      return {
        keyGen: {
          name: "RSASSA-PKCS1-v1_5",
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: "SHA-256"
        } as RsaHashedKeyGenParams,
        importAlgo: {
          name: "RSASSA-PKCS1-v1_5",
          hash: "SHA-256"
        } as RsaHashedImportParams,
        signAlgo: { name: "RSASSA-PKCS1-v1_5" } as AlgorithmIdentifier,
        sigType: "rsa" as const,
        csrSigAlg: asn1Seq(encodeOid("1.2.840.113549.1.1.11"), asn1Null())
      };
    case "rsa-4096":
      return {
        keyGen: {
          name: "RSASSA-PKCS1-v1_5",
          modulusLength: 4096,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: "SHA-256"
        } as RsaHashedKeyGenParams,
        importAlgo: {
          name: "RSASSA-PKCS1-v1_5",
          hash: "SHA-256"
        } as RsaHashedImportParams,
        signAlgo: { name: "RSASSA-PKCS1-v1_5" } as AlgorithmIdentifier,
        sigType: "rsa" as const,
        csrSigAlg: asn1Seq(encodeOid("1.2.840.113549.1.1.11"), asn1Null())
      };
    case "ecdsa-p384":
      return {
        keyGen: {
          name: "ECDSA",
          namedCurve: "P-384"
        } as EcKeyGenParams,
        importAlgo: {
          name: "ECDSA",
          namedCurve: "P-384"
        } as EcKeyImportParams,
        signAlgo: {
          name: "ECDSA",
          hash: "SHA-384"
        } as EcdsaParams,
        sigType: "ecdsa" as const,
        joseSize: 96,
        csrSigAlg: asn1Seq(encodeOid("1.2.840.10045.4.3.3"))
      };
    case "ecdsa-p256":
    default:
      return {
        keyGen: {
          name: "ECDSA",
          namedCurve: "P-256"
        } as EcKeyGenParams,
        importAlgo: {
          name: "ECDSA",
          namedCurve: "P-256"
        } as EcKeyImportParams,
        signAlgo: {
          name: "ECDSA",
          hash: "SHA-256"
        } as EcdsaParams,
        sigType: "ecdsa" as const,
        joseSize: 64,
        csrSigAlg: asn1Seq(encodeOid("1.2.840.10045.4.3.2"))
      };
  }
}

async function generateAccount(name: string, directory: string, alg: string): Promise<StoredAccount> {
  const spec = getAccountSigningSpec(alg);
  const kp = await crypto.subtle.generateKey(spec.keyGen, true, ["sign", "verify"]);
  const privateJwk = await crypto.subtle.exportKey("jwk", kp.privateKey);
  const publicJwk = await crypto.subtle.exportKey("jwk", kp.publicKey);
  return {
    alg,
    directory,
    privateJwk,
    publicJwk
  };
}

async function importAccountKeys(acc: StoredAccount): Promise<{ privateKey: CryptoKey; publicJwk: JsonWebKey }> {
  const spec = getAccountSigningSpec(acc.alg);
  const privateKey = await crypto.subtle.importKey("jwk", acc.privateJwk, spec.importAlgo, true, ["sign"]);
  return {
    privateKey,
    publicJwk: acc.publicJwk
  };
}

async function loadOrCreateAccount(env: Env, directory: string, name: string, alg: string): Promise<StoredAccount> {
  const key = accountKey(name);
  const existing = await env.CERTS.get(key);
  if (existing) {
    const parsed = safeJsonParse<StoredAccount>(await existing.text());
    if (!parsed.directory) parsed.directory = directory;
    if (!parsed.alg) parsed.alg = alg;
    return parsed;
  }
  const created = await generateAccount(name, directory, alg);
  await env.CERTS.put(key, JSON.stringify(created));
  return created;
}

async function saveAccount(env: Env, name: string, acc: StoredAccount): Promise<void> {
  await env.CERTS.put(accountKey(name), JSON.stringify(acc));
}

function jwkThumbprintInput(jwk: JsonWebKey): string {
  if (jwk.kty === "RSA") {
    return JSON.stringify({
      e: jwk.e,
      kty: jwk.kty,
      n: jwk.n
    });
  }
  if (jwk.kty === "EC") {
    return JSON.stringify({
      crv: jwk.crv,
      kty: jwk.kty,
      x: jwk.x,
      y: jwk.y
    });
  }
  throw new Error("不支持的 JWK 类型");
}

async function jwkThumbprint(jwk: JsonWebKey): Promise<string> {
  const digest = await sha256(utf8(jwkThumbprintInput(jwk)));
  return base64UrlEncode(digest);
}

function readDerLength(bytes: Uint8Array, offset: number): { len: number; next: number } {
  const first = bytes[offset];
  if ((first & 0x80) === 0) return { len: first, next: offset + 1 };
  const count = first & 0x7f;
  let len = 0;
  for (let i = 0; i < count; i++) len = (len << 8) | bytes[offset + 1 + i];
  return { len, next: offset + 1 + count };
}

function derEcdsaToJose(sig: Uint8Array, size: number): Uint8Array {
  if (sig.length === size) return sig;
  if (sig[0] !== 0x30) throw new Error("ECDSA 签名不是 DER SEQUENCE");
  let offset = 1;
  const seqLen = readDerLength(sig, offset);
  offset = seqLen.next;
  if (sig[offset] !== 0x02) throw new Error("ECDSA DER 缺少 r");
  offset += 1;
  const rLen = readDerLength(sig, offset);
  offset = rLen.next;
  let r = sig.slice(offset, offset + rLen.len);
  offset += rLen.len;
  if (sig[offset] !== 0x02) throw new Error("ECDSA DER 缺少 s");
  offset += 1;
  const sLen = readDerLength(sig, offset);
  offset = sLen.next;
  let s = sig.slice(offset, offset + sLen.len);

  const partSize = size / 2;
  while (r.length > partSize && r[0] === 0x00) r = r.slice(1);
  while (s.length > partSize && s[0] === 0x00) s = s.slice(1);

  const out = new Uint8Array(size);
  out.set(r, partSize - r.length);
  out.set(s, size - s.length);
  return out;
}

function joseEcdsaToDer(sig: Uint8Array): Uint8Array {
  const partSize = sig.length / 2;
  let r = sig.slice(0, partSize);
  let s = sig.slice(partSize);

  while (r.length > 1 && r[0] === 0x00 && (r[1] & 0x80) === 0) r = r.slice(1);
  while (s.length > 1 && s[0] === 0x00 && (s[1] & 0x80) === 0) s = s.slice(1);
  if (r[0] & 0x80) r = concatBytes(Uint8Array.of(0x00), r);
  if (s[0] & 0x80) s = concatBytes(Uint8Array.of(0x00), s);

  return asn1Seq(
    asn1(0x02, r),
    asn1(0x02, s)
  );
}

async function signAcmeJws(
  url: string,
  payload: unknown,
  acc: StoredAccount,
  nonce: string
): Promise<string> {
  const spec = getAccountSigningSpec(acc.alg);
  const imported = await importAccountKeys(acc);
  const protectedHeader: Record<string, unknown> = {
    alg: spec.jwkAlg,
    nonce,
    url
  };

  if (acc.kid) {
    protectedHeader.kid = acc.kid;
  } else {
    protectedHeader.jwk = imported.publicJwk;
  }

  const protected64 = base64UrlEncodeString(JSON.stringify(protectedHeader));
  const payloadText =
    payload === "" ? "" :
    payload === null || payload === undefined ? "" :
    JSON.stringify(payload);

  const payload64 = payloadText === "" ? "" : base64UrlEncodeString(payloadText);
  const signingInput = utf8(`${protected64}.${payload64}`);
  const rawSig = new Uint8Array(await crypto.subtle.sign(spec.signAlgo as any, imported.privateKey, signingInput));

  const joseSig =
    spec.sigType === "ecdsa"
      ? derEcdsaToJose(rawSig, spec.joseSize!)
      : rawSig;

  const body = {
    protected: protected64,
    payload: payload64,
    signature: base64UrlEncode(joseSig)
  };

  return JSON.stringify(body);
}

async function fetchDirectory(directoryUrl: string): Promise<AcmeDirectory> {
  const res = await fetch(directoryUrl);
  if (!res.ok) {
    throw new Error(`读取 ACME directory 失败: ${res.status}`);
  }
  return await res.json<AcmeDirectory>();
}

async function getNonce(dir: AcmeDirectory): Promise<string> {
  const res = await fetch(dir.newNonce, { method: "HEAD" });
  const nonce = res.headers.get("Replay-Nonce");
  if (!nonce) throw new Error("ACME 未返回 Replay-Nonce");
  return nonce;
}

async function acmePost(
  url: string,
  payload: unknown,
  acc: StoredAccount,
  dir: AcmeDirectory
): Promise<{ res: Response; data: any; text: string }> {
  const nonce = await getNonce(dir);
  const body = await signAcmeJws(url, payload, acc, nonce);

  const res = await fetch(url, {
    method: "POST",
    headers: {
      "content-type": "application/jose+json"
    },
    body
  });

  const text = await res.text();
  let data: any = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = null;
  }

  if (!res.ok) {
    const detail = data?.detail || text || `HTTP ${res.status}`;
    throw new Error(`ACME 请求失败: ${detail}`);
  }

  return { res, data, text };
}

async function acmePostAsGet(
  url: string,
  acc: StoredAccount,
  dir: AcmeDirectory
): Promise<{ res: Response; data: any; text: string }> {
  return acmePost(url, "", acc, dir);
}

async function ensureAcmeAccount(env: Env, directoryUrl: string, name: string, alg: string): Promise<StoredAccount> {
  const dir = await fetchDirectory(directoryUrl);
  const acc = await loadOrCreateAccount(env, directoryUrl, name, alg);

  if (acc.kid) return acc;

  const result = await acmePost(dir.newAccount, {
    termsOfServiceAgreed: true
  }, acc, dir);

  const kid = result.res.headers.get("Location");
  if (!kid) throw new Error("ACME 账号创建成功但未返回 Location/kid");

  acc.kid = kid;
  await saveAccount(env, name, acc);
  return acc;
}

async function doDnsPrecheck(txtName: string, txtValue: string, row: any): Promise<boolean> {
  if (row.skip_dns_precheck) return true;

  const resolvers = [row.dns_server_1, row.dns_server_2].filter(Boolean);
  const targets = resolvers.length ? resolvers : ["1.1.1.1", "8.8.8.8"];

  for (const resolver of targets) {
    const endpoint = resolver.includes("8.8.8.8") || resolver.includes("dns.google")
      ? `https://dns.google/resolve?name=${encodeURIComponent(txtName)}&type=TXT`
      : resolver.includes("1.1.1.1") || resolver.includes("cloudflare")
      ? `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(txtName)}&type=TXT`
      : `https://${resolver}/dns-query?name=${encodeURIComponent(txtName)}&type=TXT`;

    try {
      const res = await fetch(endpoint, {
        headers: {
          accept: "application/dns-json"
        }
      });
      if (!res.ok) continue;
      const data: any = await res.json();
      const answers = Array.isArray(data.Answer) ? data.Answer : [];
      for (const ans of answers) {
        const text = String(ans.data || "").replace(/^"|"$/g, "").replace(/\\"/g, '"');
        if (text === txtValue) return true;
      }
    } catch {
      // ignore and try next
    }
  }

  return false;
}

async function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function pollAuthorizationValid(
  authzUrl: string,
  acc: StoredAccount,
  dir: AcmeDirectory
): Promise<any> {
  for (let i = 0; i < 20; i++) {
    const { data } = await acmePostAsGet(authzUrl, acc, dir);
    if (data?.status === "valid") return data;
    if (data?.status === "invalid") {
      const detail = data?.challenges?.find((x: any) => x.status === "invalid")?.error?.detail || "DNS 验证失败";
      throw new Error(`授权失败: ${detail}`);
    }
    await sleep(3000);
  }
  throw new Error("等待授权 valid 超时");
}

async function pollOrderValid(
  orderUrl: string,
  acc: StoredAccount,
  dir: AcmeDirectory
): Promise<any> {
  for (let i = 0; i < 20; i++) {
    const { data } = await acmePostAsGet(orderUrl, acc, dir);
    if (data?.status === "valid") return data;
    if (data?.status === "invalid") {
      throw new Error(`订单失败: ${data?.error?.detail || "order invalid"}`);
    }
    await sleep(3000);
  }
  throw new Error("等待订单 valid 超时");
}

function buildCsrSubject(commonName: string): Uint8Array {
  return asn1Seq(
    asn1Set(
      asn1Seq(
        encodeOid("2.5.4.3"),
        asn1Utf8(commonName)
      )
    )
  );
}

function buildSubjectAltNameExtension(names: string[]): Uint8Array {
  const generalNames = asn1Seq(
    ...names.map((name) => asn1(0x82, utf8(name)))
  );
  return asn1Seq(
    encodeOid("2.5.29.17"),
    asn1OctetString(generalNames)
  );
}

async function generateCsr(
  commonName: string,
  allNames: string[],
  certAlg: string
): Promise<{
  csrDer: Uint8Array;
  privatePem: string;
  publicPem: string;
}> {
  const spec = getCertSigningSpec(certAlg);
  const kp = await crypto.subtle.generateKey(spec.keyGen, true, ["sign", "verify"]);

  const spki = new Uint8Array(await crypto.subtle.exportKey("spki", kp.publicKey));
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", kp.privateKey));

  const subject = buildCsrSubject(commonName);
  const sanExt = buildSubjectAltNameExtension(allNames);
  const extReq = asn1Seq(
    encodeOid("1.2.840.113549.1.9.14"),
    asn1Set(
      asn1Seq(sanExt)
    )
  );

  const cri = asn1Seq(
    asn1Int(0),
    subject,
    spki,
    asn1Ctx(0, asn1Set(extReq))
  );

  const rawSig = new Uint8Array(await crypto.subtle.sign(spec.signAlgo as any, kp.privateKey, cri));
  const csrSig =
    spec.sigType === "ecdsa" && rawSig.length === spec.joseSize
      ? joseEcdsaToDer(rawSig)
      : rawSig;

  const csrDer = asn1Seq(
    cri,
    spec.csrSigAlg,
    asn1BitString(csrSig)
  );

  return {
    csrDer,
    privatePem: derToPem("PRIVATE KEY", pkcs8),
    publicPem: derToPem("PUBLIC KEY", spki)
  };
}

function parseDerNode(bytes: Uint8Array, offset: number): {
  tag: number;
  length: number;
  headerLen: number;
  start: number;
  end: number;
  valueStart: number;
} {
  const tag = bytes[offset];
  const lenInfo = readDerLength(bytes, offset + 1);
  const headerLen = lenInfo.next - offset;
  const start = offset;
  const valueStart = offset + headerLen;
  const end = valueStart + lenInfo.len;
  return { tag, length: lenInfo.len, headerLen, start, end, valueStart };
}

function parseChildNodes(bytes: Uint8Array, start: number, end: number) {
  const nodes: ReturnType<typeof parseDerNode>[] = [];
  let offset = start;
  while (offset < end) {
    const n = parseDerNode(bytes, offset);
    nodes.push(n);
    offset = n.end;
  }
  return nodes;
}

function derTimeToIso(bytes: Uint8Array, node: ReturnType<typeof parseDerNode>): string | null {
  const raw = textDecoder.decode(bytes.slice(node.valueStart, node.end));
  if (node.tag === 0x17) {
    const yy = parseInt(raw.slice(0, 2), 10);
    const year = yy >= 50 ? 1900 + yy : 2000 + yy;
    const iso = `${year}-${raw.slice(2, 4)}-${raw.slice(4, 6)}T${raw.slice(6, 8)}:${raw.slice(8, 10)}:${raw.slice(10, 12)}Z`;
    return iso;
  }
  if (node.tag === 0x18) {
    const iso = `${raw.slice(0, 4)}-${raw.slice(4, 6)}-${raw.slice(6, 8)}T${raw.slice(8, 10)}:${raw.slice(10, 12)}:${raw.slice(12, 14)}Z`;
    return iso;
  }
  return null;
}

function extractLeafValidity(certPem: string): { notBefore: string | null; notAfter: string | null } {
  try {
    const der = pemToDer(certPem);
    const root = parseDerNode(der, 0);
    const rootChildren = parseChildNodes(der, root.valueStart, root.end);
    const tbs = rootChildren[0];
    const tbsChildren = parseChildNodes(der, tbs.valueStart, tbs.end);

    const hasVersion = tbsChildren[0]?.tag === 0xa0;
    const validityNode = hasVersion ? tbsChildren[4] : tbsChildren[3];
    const validityChildren = parseChildNodes(der, validityNode.valueStart, validityNode.end);

    const notBefore = derTimeToIso(der, validityChildren[0]) || null;
    const notAfter = derTimeToIso(der, validityChildren[1]) || null;
    return { notBefore, notAfter };
  } catch {
    return { notBefore: null, notAfter: null };
  }
}

async function savePendingState(env: Env, state: PendingState): Promise<void> {
  await env.CERTS.put(stateKey(state.domainId), JSON.stringify(state));
}

async function loadPendingState(env: Env, domainId: number): Promise<PendingState | null> {
  const obj = await env.CERTS.get(stateKey(domainId));
  if (!obj) return null;
  return safeJsonParse<PendingState>(await obj.text());
}

async function deletePendingState(env: Env, domainId: number): Promise<void> {
  await env.CERTS.delete(stateKey(domainId));
}

async function listDomains(env: Env): Promise<Response> {
  const rs = await env.DB.prepare(`SELECT * FROM domains ORDER BY id DESC`).all();
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
  if (!body.domain) return json({ ok: false, error: "domain 不能为空" }, 400);

  const sans = JSON.stringify((body.sans || []).map((x: string) => normalizeDomain(x)));
  const domain = normalizeDomain(body.domain);
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
    domain,
    sans,
    body.acme_directory || "https://acme-staging-v02.api.letsencrypt.org/directory",
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
  const row = await env.DB.prepare(`SELECT * FROM domains WHERE id = ?`).bind(id).first();
  if (!row) return json({ ok: false, error: "域名不存在" }, 404);
  return json({ ok: true, item: row as unknown as JsonMap });
}

async function startIssue(env: Env, id: string): Promise<Response> {
  const row: any = await env.DB.prepare(`SELECT * FROM domains WHERE id = ?`).bind(id).first();
  if (!row) return json({ ok: false, error: "域名不存在" }, 404);

  const domainId = Number(id);
  const domain = normalizeDomain(row.domain);
  const sans = safeJsonParse<string[]>(row.sans_json || "[]").map(normalizeDomain);
  const identifiers = [domain, ...sans].filter((v, i, a) => a.indexOf(v) === i);

  if (row.validation_mode !== "manual") {
    return json({ ok: false, error: "这份真实版代码当前只支持手动 DNS 模式" }, 400);
  }

  const directoryUrl = row.acme_directory || "https://acme-staging-v02.api.letsencrypt.org/directory";
  const dir = await fetchDirectory(directoryUrl);
  const account = await ensureAcmeAccount(
    env,
    directoryUrl,
    row.acme_account_name || "default",
    row.account_key_algorithm || "ecdsa-p256"
  );

  const orderPayload = {
    identifiers: identifiers.map((name) => ({ type: "dns", value: name }))
  };

  const orderResult = await acmePost(dir.newOrder, orderPayload, account, dir);
  const orderUrl = orderResult.res.headers.get("Location");
  const orderData = orderResult.data;

  if (!orderUrl) throw new Error("newOrder 未返回 Location");
  if (!orderData?.authorizations?.length) throw new Error("newOrder 未返回 authorizations");
  if (!orderData?.finalize) throw new Error("newOrder 未返回 finalize URL");

  const publicJwk = (await importAccountKeys(account)).publicJwk;
  const thumbprint = await jwkThumbprint(publicJwk);

  const challenges: PendingChallenge[] = [];

  for (const authzUrl of orderData.authorizations as string[]) {
    const authz = await acmePostAsGet(authzUrl, account, dir);
    const identifier = String(authz.data?.identifier?.value || "");
    const dnsChallenge = (authz.data?.challenges || []).find((x: any) => x.type === "dns-01");
    if (!dnsChallenge?.url || !dnsChallenge?.token) {
      throw new Error(`域名 ${identifier} 未找到 dns-01 challenge`);
    }

    const keyAuthorization = `${dnsChallenge.token}.${thumbprint}`;
    const digest = await sha256(utf8(keyAuthorization));
    const txtValue = base64UrlEncode(digest);
    challenges.push({
      identifier,
      authzUrl,
      challengeUrl: dnsChallenge.url,
      txtName: `_acme-challenge.${identifier}`,
      txtValue
    });
  }

  const pending: PendingState = {
    domainId,
    domain,
    identifiers,
    orderUrl,
    finalizeUrl: orderData.finalize,
    accountName: row.acme_account_name || "default",
    directoryUrl,
    accountAlg: row.account_key_algorithm || "ecdsa-p256",
    certAlg: row.cert_key_algorithm || "ecdsa-p256",
    challenges,
    createdAt: new Date().toISOString()
  };

  await savePendingState(env, pending);

  await env.DB.prepare(`
    UPDATE domains
    SET status = 'pending_dns',
        last_error = '',
        updated_at = CURRENT_TIMESTAMP
    WHERE id = ?
  `).bind(domainId).run();

  return json({
    ok: true,
    step: "pending_dns",
    message: "请先手动添加 TXT 记录，全部生效后再点继续验证。",
    dns_records: challenges.map((c) => ({
      type: "TXT",
      name: c.txtName,
      value: c.txtValue,
      for_domain: c.identifier
    }))
  });
}

async function finalizeIssue(env: Env, id: string): Promise<Response> {
  const row: any = await env.DB.prepare(`SELECT * FROM domains WHERE id = ?`).bind(id).first();
  if (!row) return json({ ok: false, error: "域名不存在" }, 404);

  const domainId = Number(id);
  const pending = await loadPendingState(env, domainId);
  if (!pending) {
    return json({ ok: false, error: "没有找到待验证的 ACME 状态，请先点开始签发" }, 400);
  }

  const dir = await fetchDirectory(pending.directoryUrl);
  const account = await loadOrCreateAccount(env, pending.directoryUrl, pending.accountName, pending.accountAlg);

  if (!account.kid) {
    return json({ ok: false, error: "ACME 账号缺少 kid，请重新开始签发" }, 400);
  }

  if (!row.skip_dns_precheck) {
    for (const item of pending.challenges) {
      const ok = await doDnsPrecheck(item.txtName, item.txtValue, row);
      if (!ok) {
        return json({
          ok: false,
          error: `DNS 预检查未通过：${item.txtName} 还没有解析到要求的 TXT 值`
        }, 400);
      }
    }
  }

  for (const item of pending.challenges) {
    await acmePost(item.challengeUrl, {}, account, dir);
    await pollAuthorizationValid(item.authzUrl, account, dir);
  }

  const csr = await generateCsr(
    pending.domain,
    pending.identifiers,
    pending.certAlg
  );

  await acmePost(pending.finalizeUrl, {
    csr: base64UrlEncode(csr.csrDer)
  }, account, dir);

  const finalOrder = await pollOrderValid(pending.orderUrl, account, dir);
  const certUrl = finalOrder?.certificate;
  if (!certUrl) throw new Error("订单已 valid，但未返回 certificate URL");

  const certResp = await acmePostAsGet(certUrl, account, dir);
  const fullchainPem = certResp.text;
  const certs = splitPemChain(fullchainPem);
  if (!certs.length) throw new Error("下载到的证书链为空");

  const leafPem = certs[0];
  const chainPem = certs.slice(1).join("\n");
  const validity = extractLeafValidity(leafPem);

  const base = `certs/${pending.domain}/${Date.now()}`;
  await env.CERTS.put(`${base}/cert.pem`, leafPem);
  await env.CERTS.put(`${base}/chain.pem`, chainPem);
  await env.CERTS.put(`${base}/fullchain.pem`, fullchainPem);
  await env.CERTS.put(`${base}/privkey.pem`, csr.privatePem);
  await env.CERTS.put(`${base}/pubkey.pem`, csr.publicPem);

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
    domainId,
    `${base}/cert.pem`,
    `${base}/chain.pem`,
    `${base}/fullchain.pem`,
    `${base}/privkey.pem`,
    `${base}/pubkey.pem`,
    "",
    validity.notBefore,
    validity.notAfter
  ).run();

  await env.DB.prepare(`
    UPDATE domains
    SET status = 'issued',
        expires_at = ?,
        last_error = '',
        updated_at = CURRENT_TIMESTAMP
    WHERE id = ?
  `).bind(validity.notAfter, domainId).run();

  await env.DB.prepare(`
    INSERT INTO renew_logs (domain_id, action, success, message)
    VALUES (?, 'issue', 1, 'issued by real letsencrypt staging flow')
  `).bind(domainId).run();

  await deletePendingState(env, domainId);

  return json({
    ok: true,
    step: "issued",
    message: "已从 Let’s Encrypt Staging 成功签发并写入 R2。",
    expires_at: validity.notAfter,
    certificate_url: certUrl
  });
}

async function getLatestCert(env: Env, id: string): Promise<Response> {
  const cert: any = await env.DB.prepare(`
    SELECT * FROM certificates
    WHERE domain_id = ?
    ORDER BY id DESC
    LIMIT 1
  `).bind(id).first();

  if (!cert) return json({ ok: false, error: "还没有证书" }, 404);

  const certObj = await env.CERTS.get(cert.cert_path);
  const chainObj = await env.CERTS.get(cert.chain_path);
  const fullchainObj = await env.CERTS.get(cert.fullchain_path);
  const privkeyObj = await env.CERTS.get(cert.privkey_path);
  const pubkeyObj = await env.CERTS.get(cert.pubkey_path);

  return json({
    ok: true,
    item: cert,
    files: {
      cert: certObj ? await certObj.text() : null,
      chain: chainObj ? await chainObj.text() : null,
      fullchain: fullchainObj ? await fullchainObj.text() : null,
      privkey: privkeyObj ? await privkeyObj.text() : null,
      pubkey: pubkeyObj ? await pubkeyObj.text() : null
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

  if (method === "OPTIONS" && path.startsWith("/api/")) {
    return new Response(null, { status: 204 });
  }

  if (!path.startsWith("/api/")) {
    return context.next();
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

    return json({ ok: false, error: "API Not Found" }, 404);
  } catch (error) {
    const message = error instanceof Error ? error.message : "服务器内部错误";

    const maybeId = path.match(/^\/api\/domains\/(\d+)\/(issue|finalize)$/);
    if (maybeId) {
      try {
        await env.DB.prepare(`
          UPDATE domains
          SET last_error = ?, status = 'error', updated_at = CURRENT_TIMESTAMP
          WHERE id = ?
        `).bind(message, Number(maybeId[1])).run();
      } catch {
        // ignore
      }
    }

    return json({ ok: false, error: message }, 500);
  }
};
