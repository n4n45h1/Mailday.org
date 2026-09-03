import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { x25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha512 } from "@noble/hashes/sha2.js";
import { ml_kem768_x25519 } from "@noble/post-quantum/hybrid.js";

interface Env {
  DB: D1Database;
  MAIL: R2Bucket;
  ASSETS: Fetcher;
  MAIL_DOMAIN: string;
  MAILBOX_TTL_DAYS: string;
  MESSAGE_TTL_DAYS: string;
}

interface MailboxRow {
  mailbox_id: string;
  address: string;
  auth_public_key: string;
  encryption_public_key: string;
  encryption_mode: "none" | "standard" | "strong";
  retention_seconds: number;
  expires_at: number;
}

interface SessionRow {
  mailbox_id: string;
}

interface ChallengeRow {
  mailbox_id: string;
  challenge_hash: string;
  expires_at: number;
  auth_public_key: string;
}

interface MessageRow {
  message_id: string;
  object_key: string;
  received_at: number;
  expires_at: number;
  size: number;
}

const encoder = new TextEncoder();
const MAX_MAIL_BYTES = 25 * 1024 * 1024;
const JSON_HEADERS = { "content-type": "application/json; charset=utf-8" };

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), { status, headers: JSON_HEADERS });
}

function randomId(bytes = 18): string {
  const value = crypto.getRandomValues(new Uint8Array(bytes));
  return toBase64Url(value);
}

function toBase64Url(value: ArrayBuffer | Uint8Array): string {
  const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromBase64Url(value: string): Uint8Array<ArrayBuffer> {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

async function sha256(value: string): Promise<string> {
  return toBase64Url(await crypto.subtle.digest("SHA-256", encoder.encode(value)));
}

function parseJwk(value: unknown, use: "sig" | "enc", curve = "P-256"): JsonWebKey | null {
  if (!value || typeof value !== "object") return null;
  const key = value as JsonWebKey;
  if (key.kty !== "EC" || key.crv !== curve || !key.x || !key.y || key.d) return null;
  if (use === "sig" && key.key_ops && !key.key_ops.includes("verify")) return null;
  if (use === "enc" && key.key_ops?.length) return null;
  return key;
}

function parseModernEncryptionKey(value: unknown, mode: "standard" | "strong"): { algorithm: string; key: string } | null {
  if (!value || typeof value !== "object") return null;
  const key = value as { algorithm?: unknown; key?: unknown };
  const algorithm = mode === "strong" ? "XWING-MLKEM768-X25519" : "X25519";
  if (key.algorithm !== algorithm || typeof key.key !== "string") return null;
  try {
    const expectedLength = mode === "strong" ? 1216 : 32;
    return fromBase64Url(key.key).length === expectedLength ? { algorithm, key: key.key } : null;
  } catch {
    return null;
  }
}

async function readJson(request: Request): Promise<Record<string, unknown> | null> {
  if (!request.headers.get("content-type")?.toLowerCase().startsWith("application/json")) return null;
  try {
    const value = await request.json();
    return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
  } catch {
    return null;
  }
}

async function createMailbox(request: Request, env: Env): Promise<Response> {
  const body = await readJson(request);
  const encryptionMode = body?.encryptionMode;
  if (encryptionMode !== "none" && encryptionMode !== "standard" && encryptionMode !== "strong") {
    return json({ error: "Invalid encryption mode" }, 400);
  }
  const authKey = parseJwk(body?.authPublicKey, "sig");
  const encryptionKey = encryptionMode === "none" ? null : parseModernEncryptionKey(body?.encryptionPublicKey, encryptionMode);
  if (!authKey || (encryptionMode !== "none" && !encryptionKey)) return json({ error: "Invalid public keys" }, 400);

  const durations: Record<string, number> = {
    "1h": 3600,
    "1d": 86400,
    "7d": 604800,
    forever: 0,
  };
  const retentionSeconds = typeof body?.expiresIn === "string" ? durations[body.expiresIn] : undefined;
  if (retentionSeconds === undefined) return json({ error: "Invalid expiry" }, 400);

  const now = Date.now();
  const mailboxId = randomId();
  const requestedLocalPart = typeof body?.localPart === "string" ? body.localPart.trim().toLowerCase() : "";
  if (requestedLocalPart && !/^[a-z0-9](?:[a-z0-9._-]{1,30}[a-z0-9])?$/.test(requestedLocalPart)) {
    return json({ error: "Address must be 3-32 characters using a-z, 0-9, dot, underscore, or hyphen" }, 400);
  }
  if (["abuse", "admin", "mailer-daemon", "postmaster", "security", "support"].includes(requestedLocalPart)) {
    return json({ error: "This address is reserved" }, 400);
  }
  const localPart = requestedLocalPart || randomId(8).toLowerCase().replace(/[_-]/g, "q");
  const address = `${localPart}@${env.MAIL_DOMAIN.toLowerCase()}`;
  const expiresAt = retentionSeconds === 0 ? 253_402_300_799_999 : now + retentionSeconds * 1000;

  const existing = await env.DB.prepare("SELECT 1 FROM mailboxes WHERE address = ?").bind(address).first();
  if (existing) return json({ error: "Address is already in use" }, 409);

  await env.DB.prepare(
    `INSERT INTO mailboxes
     (mailbox_id, address, auth_public_key, encryption_public_key, encryption_mode, retention_seconds, created_at, expires_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  ).bind(
    mailboxId, address, JSON.stringify(authKey), JSON.stringify(encryptionKey ?? {}),
    encryptionMode, retentionSeconds, now, expiresAt,
  ).run();

  return json({ address, expiresAt, encryptionMode }, 201);
}

async function issueChallenge(request: Request, env: Env): Promise<Response> {
  const body = await readJson(request);
  const address = typeof body?.address === "string" ? body.address.trim().toLowerCase() : "";
  if (!address || address.length > 254) return json({ error: "Invalid address" }, 400);

  const mailbox = await env.DB.prepare(
    "SELECT mailbox_id FROM mailboxes WHERE address = ? AND expires_at > ?",
  ).bind(address, Date.now()).first<{ mailbox_id: string }>();
  if (!mailbox) return json({ error: "Inbox not found" }, 404);

  const challengeId = randomId();
  const challenge = randomId(32);
  const expiresAt = Date.now() + 60_000;
  await env.DB.prepare(
    "INSERT INTO challenges (challenge_id, mailbox_id, challenge_hash, expires_at) VALUES (?, ?, ?, ?)",
  ).bind(challengeId, mailbox.mailbox_id, await sha256(challenge), expiresAt).run();
  return json({ challengeId, challenge, expiresAt });
}

async function verifyChallenge(request: Request, env: Env): Promise<Response> {
  const body = await readJson(request);
  const challengeId = typeof body?.challengeId === "string" ? body.challengeId : "";
  const challenge = typeof body?.challenge === "string" ? body.challenge : "";
  const signature = typeof body?.signature === "string" ? body.signature : "";
  if (!challengeId || !challenge || !signature) return json({ error: "Invalid proof" }, 400);

  const row = await env.DB.prepare(
    `SELECT c.mailbox_id, c.challenge_hash, c.expires_at, m.auth_public_key
     FROM challenges c JOIN mailboxes m ON m.mailbox_id = c.mailbox_id
     WHERE c.challenge_id = ?`,
  ).bind(challengeId).first<ChallengeRow>();
  if (!row || row.expires_at <= Date.now() || row.challenge_hash !== await sha256(challenge)) {
    return json({ error: "Invalid or expired proof" }, 401);
  }

  let valid = false;
  try {
    const publicKey = await crypto.subtle.importKey(
      "jwk", JSON.parse(row.auth_public_key), { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"],
    );
    valid = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" }, publicKey, fromBase64Url(signature), encoder.encode(challenge),
    );
  } catch {
    valid = false;
  }
  if (!valid) return json({ error: "Invalid or expired proof" }, 401);

  const deleted = await env.DB.prepare(
    "DELETE FROM challenges WHERE challenge_id = ? AND expires_at > ?",
  ).bind(challengeId, Date.now()).run();
  if (deleted.meta.changes !== 1) return json({ error: "Invalid or expired proof" }, 401);

  const token = randomId(32);
  const expiresAt = Date.now() + 12 * 60 * 60 * 1000;
  await env.DB.prepare(
    "INSERT INTO sessions (session_id, mailbox_id, token_hash, expires_at) VALUES (?, ?, ?, ?)",
  ).bind(randomId(), row.mailbox_id, await sha256(token), expiresAt).run();
  return json({ token, expiresAt });
}

async function authenticate(request: Request, env: Env): Promise<SessionRow | null> {
  const authorization = request.headers.get("authorization") ?? "";
  if (!authorization.startsWith("Bearer ")) return null;
  const token = authorization.slice(7);
  if (token.length < 32 || token.length > 128) return null;
  return env.DB.prepare(
    "SELECT mailbox_id FROM sessions WHERE token_hash = ? AND expires_at > ?",
  ).bind(await sha256(token), Date.now()).first<SessionRow>();
}

async function listMessages(request: Request, env: Env, session: SessionRow): Promise<Response> {
  const mailbox = await env.DB.prepare(
    "SELECT address, expires_at FROM mailboxes WHERE mailbox_id = ?",
  ).bind(session.mailbox_id).first<{ address: string; expires_at: number }>();
  if (!mailbox) return json({ error: "Inbox not found" }, 404);

  const result = await env.DB.prepare(
    `SELECT message_id, received_at, expires_at, size FROM messages
     WHERE mailbox_id = ? AND expires_at > ? ORDER BY received_at DESC LIMIT 100`,
  ).bind(session.mailbox_id, Date.now()).all<Omit<MessageRow, "object_key">>();
  return json({ address: mailbox.address, expiresAt: mailbox.expires_at, messages: result.results });
}

async function getMessage(env: Env, session: SessionRow, messageId: string): Promise<Response> {
  const message = await env.DB.prepare(
    "SELECT object_key FROM messages WHERE message_id = ? AND mailbox_id = ? AND expires_at > ?",
  ).bind(messageId, session.mailbox_id, Date.now()).first<{ object_key: string }>();
  if (!message) return json({ error: "Message not found" }, 404);
  const object = await env.MAIL.get(message.object_key);
  if (!object) return json({ error: "Message not found" }, 404);
  return new Response(object.body, { headers: { "content-type": "application/json", "cache-control": "no-store" } });
}

async function deleteMessage(env: Env, session: SessionRow, messageId: string): Promise<Response> {
  const message = await env.DB.prepare(
    "SELECT object_key FROM messages WHERE message_id = ? AND mailbox_id = ?",
  ).bind(messageId, session.mailbox_id).first<{ object_key: string }>();
  if (!message) return new Response(null, { status: 204 });
  await env.MAIL.delete(message.object_key);
  await env.DB.prepare("DELETE FROM messages WHERE message_id = ? AND mailbox_id = ?")
    .bind(messageId, session.mailbox_id).run();
  return new Response(null, { status: 204 });
}

async function handleApi(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  if (request.method === "POST" && url.pathname === "/api/mailboxes") return createMailbox(request, env);
  if (request.method === "POST" && url.pathname === "/api/auth/challenge") return issueChallenge(request, env);
  if (request.method === "POST" && url.pathname === "/api/auth/verify") return verifyChallenge(request, env);

  const session = await authenticate(request, env);
  if (!session) return json({ error: "Unauthorized" }, 401);
  if (request.method === "GET" && url.pathname === "/api/messages") return listMessages(request, env, session);
  const match = url.pathname.match(/^\/api\/messages\/([A-Za-z0-9_-]+)$/);
  if (match && request.method === "GET") return getMessage(env, session, match[1]);
  if (match && request.method === "DELETE") return deleteMessage(env, session, match[1]);
  return json({ error: "Not found" }, 404);
}

async function encryptLegacyMail(raw: ArrayBuffer, publicJwk: JsonWebKey): Promise<string> {
  const curve = publicJwk.crv === "P-384" ? "P-384" : "P-256";
  const recipientKey = await crypto.subtle.importKey(
    "jwk", publicJwk, { name: "ECDH", namedCurve: curve }, false, [],
  );
  const ephemeral = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: curve }, true, ["deriveKey"],
  ) as CryptoKeyPair;
  const wrappingKey = await crypto.subtle.deriveKey(
    { name: "ECDH", public: recipientKey } as unknown as SubtleCryptoDeriveKeyAlgorithm, ephemeral.privateKey,
    { name: "AES-GCM", length: 256 }, false, ["encrypt"],
  );
  const contentKey = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 }, true, ["encrypt"],
  ) as CryptoKey;
  const contentIv = crypto.getRandomValues(new Uint8Array(12));
  const wrappedKeyIv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv: contentIv }, contentKey, raw);
  const rawContentKey = await crypto.subtle.exportKey("raw", contentKey) as ArrayBuffer;
  const wrappedKey = await crypto.subtle.encrypt({ name: "AES-GCM", iv: wrappedKeyIv }, wrappingKey, rawContentKey);
  const ephemeralPublicKey = await crypto.subtle.exportKey("jwk", ephemeral.publicKey) as JsonWebKey;

  return JSON.stringify({
    version: 1,
    algorithm: `${curve}/ECDH+A256GCM`,
    ephemeralPublicKey,
    contentIv: toBase64Url(contentIv),
    wrappedKeyIv: toBase64Url(wrappedKeyIv),
    wrappedKey: toBase64Url(wrappedKey),
    ciphertext: toBase64Url(ciphertext),
  });
}

function deriveMessageKey(sharedSecret: Uint8Array, nonce: Uint8Array, algorithm: string): Uint8Array {
  return hkdf(sha512, sharedSecret, nonce, encoder.encode(`mailday:${algorithm}:v1`), 32);
}

function encryptModernMail(raw: ArrayBuffer, publicKey: { algorithm: string; key: string }): string {
  const nonce = crypto.getRandomValues(new Uint8Array(24));
  const recipientPublicKey = fromBase64Url(publicKey.key);
  let sharedSecret: Uint8Array;
  let encapsulation: Uint8Array;

  if (publicKey.algorithm === "XWING-MLKEM768-X25519") {
    const encapsulated = ml_kem768_x25519.encapsulate(recipientPublicKey);
    sharedSecret = encapsulated.sharedSecret;
    encapsulation = encapsulated.cipherText;
  } else {
    const ephemeral = x25519.keygen();
    sharedSecret = x25519.getSharedSecret(ephemeral.secretKey, recipientPublicKey);
    encapsulation = ephemeral.publicKey;
    ephemeral.secretKey.fill(0);
  }

  const algorithm = publicKey.algorithm === "XWING-MLKEM768-X25519"
    ? "XWING-MLKEM768-X25519+XCHACHA20POLY1305"
    : "X25519+XCHACHA20POLY1305";
  const contentKey = deriveMessageKey(sharedSecret, nonce, algorithm);
  const aad = encoder.encode(`mailday-envelope:${algorithm}:v2`);
  const ciphertext = xchacha20poly1305(contentKey, nonce, aad).encrypt(new Uint8Array(raw));
  sharedSecret.fill(0);
  contentKey.fill(0);

  return JSON.stringify({
    version: 2,
    algorithm,
    encapsulation: toBase64Url(encapsulation),
    nonce: toBase64Url(nonce),
    ciphertext: toBase64Url(ciphertext),
  });
}

async function receiveEmail(message: ForwardableEmailMessage, env: Env): Promise<void> {
  const address = message.to.trim().toLowerCase();
  const mailbox = await env.DB.prepare(
    "SELECT mailbox_id, encryption_public_key, encryption_mode, retention_seconds, expires_at FROM mailboxes WHERE address = ?",
  ).bind(address).first<Pick<MailboxRow, "mailbox_id" | "encryption_public_key" | "encryption_mode" | "retention_seconds" | "expires_at">>();
  if (!mailbox || mailbox.expires_at <= Date.now()) {
    message.setReject("Mailbox does not exist");
    return;
  }
  if (message.rawSize > MAX_MAIL_BYTES) {
    message.setReject("Message is too large");
    return;
  }

  const raw = await new Response(message.raw).arrayBuffer();
  const storedPublicKey = JSON.parse(mailbox.encryption_public_key);
  const encrypted = mailbox.encryption_mode === "none"
    ? JSON.stringify({ version: 1, algorithm: "NONE", raw: toBase64Url(raw) })
    : typeof storedPublicKey.algorithm === "string"
      ? encryptModernMail(raw, storedPublicKey)
      : await encryptLegacyMail(raw, storedPublicKey);
  const now = Date.now();
  const expiresAt = mailbox.retention_seconds === 0
    ? mailbox.expires_at
    : Math.min(mailbox.expires_at, now + mailbox.retention_seconds * 1000);
  const messageId = randomId();
  const objectKey = `${mailbox.mailbox_id}/${messageId}.json`;
  await env.MAIL.put(objectKey, encrypted, { httpMetadata: { contentType: "application/json" } });
  try {
    await env.DB.prepare(
      "INSERT INTO messages (message_id, mailbox_id, object_key, received_at, expires_at, size) VALUES (?, ?, ?, ?, ?, ?)",
    ).bind(messageId, mailbox.mailbox_id, objectKey, now, expiresAt, message.rawSize).run();
  } catch (error) {
    await env.MAIL.delete(objectKey);
    throw error;
  }
}

async function cleanup(env: Env): Promise<void> {
  const now = Date.now();
  const expired = await env.DB.prepare(
    "SELECT message_id, object_key FROM messages WHERE expires_at <= ? LIMIT 100",
  ).bind(now).all<Pick<MessageRow, "message_id" | "object_key">>();
  if (expired.results.length) {
    await env.MAIL.delete(expired.results.map((message) => message.object_key));
    const placeholders = expired.results.map(() => "?").join(",");
    await env.DB.prepare(`DELETE FROM messages WHERE message_id IN (${placeholders})`)
      .bind(...expired.results.map((message) => message.message_id)).run();
  }
  await env.DB.batch([
    env.DB.prepare("DELETE FROM challenges WHERE expires_at <= ?").bind(now),
    env.DB.prepare("DELETE FROM sessions WHERE expires_at <= ?").bind(now),
    env.DB.prepare("DELETE FROM mailboxes WHERE expires_at <= ? AND NOT EXISTS (SELECT 1 FROM messages WHERE messages.mailbox_id = mailboxes.mailbox_id)").bind(now),
  ]);
}

function secure(response: Response): Response {
  const secured = new Response(response.body, response);
  secured.headers.set("cache-control", "no-store");
  secured.headers.set("content-security-policy", "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data: blob:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");
  secured.headers.set("referrer-policy", "no-referrer");
  secured.headers.set("x-content-type-options", "nosniff");
  secured.headers.set("x-frame-options", "DENY");
  secured.headers.set("permissions-policy", "camera=(), microphone=(), geolocation=() ");
  return secured;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    try {
      const response = url.pathname.startsWith("/api/")
        ? await handleApi(request, env)
        : await env.ASSETS.fetch(request);
      return secure(response);
    } catch {
      return secure(json({ error: "Request failed" }, 500));
    }
  },
  async email(message: ForwardableEmailMessage, env: Env): Promise<void> {
    await receiveEmail(message, env);
  },
  async scheduled(_controller: ScheduledController, env: Env, context: ExecutionContext): Promise<void> {
    context.waitUntil(cleanup(env));
  },
} satisfies ExportedHandler<Env>;
