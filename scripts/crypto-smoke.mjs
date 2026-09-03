import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { x25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha512 } from "@noble/hashes/sha2.js";
import { ml_kem768_x25519 } from "@noble/post-quantum/hybrid.js";
import PostalMime from "postal-mime";

const origin = process.env.MAILDAY_TEST_ORIGIN || "http://127.0.0.1:8787";
const encoder = new TextEncoder();

const encode = (value) => Buffer.from(value).toString("base64url");
const decode = (value) => new Uint8Array(Buffer.from(value, "base64url"));

async function post(path, body) {
  return fetch(`${origin}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

function encryptionKeys(mode) {
  if (mode === "none") return {};
  const pair = mode === "strong" ? ml_kem768_x25519.keygen() : x25519.keygen();
  const algorithm = mode === "strong" ? "XWING-MLKEM768-X25519" : "X25519";
  return {
    privateKey: { algorithm, key: encode(pair.secretKey) },
    publicKey: { algorithm, key: encode(pair.publicKey) },
  };
}

function decrypt(envelope, privateKey) {
  if (envelope.algorithm === "NONE") return decode(envelope.raw);
  const encapsulation = decode(envelope.encapsulation);
  const sharedSecret = privateKey.algorithm === "XWING-MLKEM768-X25519"
    ? ml_kem768_x25519.decapsulate(encapsulation, decode(privateKey.key))
    : x25519.getSharedSecret(decode(privateKey.key), encapsulation);
  const nonce = decode(envelope.nonce);
  const key = hkdf(sha512, sharedSecret, nonce, encoder.encode(`mailday:${envelope.algorithm}:v1`), 32);
  return xchacha20poly1305(key, nonce, encoder.encode(`mailday-envelope:${envelope.algorithm}:v2`))
    .decrypt(decode(envelope.ciphertext));
}

async function run(mode) {
  const auth = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const encryption = encryptionKeys(mode);
  let response = await post("/api/mailboxes", {
    localPart: `smoke-${mode}-${Date.now()}`,
    expiresIn: "1h",
    encryptionMode: mode,
    authPublicKey: await crypto.subtle.exportKey("jwk", auth.publicKey),
    encryptionPublicKey: encryption.publicKey,
  });
  if (response.status !== 201) throw new Error(`${mode} create failed: ${await response.text()}`);
  const mailbox = await response.json();
  const marker = `readable-${mode}-${Date.now()}`;
  const mime = [
    "From: Test Sender <sender@example.com>",
    `To: ${mailbox.address}`,
    `Message-ID: <${marker}@example.com>`,
    "MIME-Version: 1.0",
    `Subject: ${mode} test`,
    "Content-Type: text/html; charset=utf-8",
    "Content-Transfer-Encoding: quoted-printable",
    "",
    `<h2>${marker.replace(/-/g, "=2D")}</h2>`,
  ].join("\r\n");
  response = await fetch(`${origin}/cdn-cgi/handler/email?from=sender%40example.com&to=${encodeURIComponent(mailbox.address)}`, { method: "POST", body: mime });
  if (!response.ok) throw new Error(`${mode} ingress failed: ${await response.text()}`);

  response = await post("/api/auth/challenge", { address: mailbox.address });
  const challenge = await response.json();
  const signature = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, auth.privateKey, encoder.encode(challenge.challenge));
  response = await post("/api/auth/verify", { ...challenge, signature: encode(signature) });
  const session = await response.json();
  const headers = { authorization: `Bearer ${session.token}` };
  const list = await fetch(`${origin}/api/messages`, { headers }).then((value) => value.json());
  const envelope = await fetch(`${origin}/api/messages/${list.messages[0].message_id}`, { headers }).then((value) => value.json());
  const parsed = await PostalMime.parse(decrypt(envelope, encryption.privateKey));
  if (parsed.subject !== `${mode} test` || !parsed.html?.includes(marker)) throw new Error(`${mode} MIME mismatch`);
  console.log(`${mode}: ${envelope.algorithm} OK`);
}

for (const mode of ["none", "standard", "strong"]) await run(mode);
