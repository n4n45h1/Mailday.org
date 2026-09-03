import PostalMime from "postal-mime";
import DOMPurify from "dompurify";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { x25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha512 } from "@noble/hashes/sha2.js";
import { ml_kem768_x25519 } from "@noble/post-quantum/hybrid.js";
import { argon2id } from "hash-wasm";

const $ = (selector) => document.querySelector(selector);
const encoder = new TextEncoder();
const decoder = new TextDecoder();
let credentials = null;
let sessionToken = null;
let language = localStorage.getItem("mailday-language") || (navigator.language.startsWith("ja") ? "ja" : "en");

const translations = {
  ja: {
    hero: "メールの中身は、<br><i>あなただけのもの。</i>", lead: "受信した瞬間に暗号化し、復号はこの端末だけで行います。運営者にも本文を読むための鍵はありません。",
    addressLabel: "CUSTOM ADDRESS（任意）", expiryLabel: "有効期限", oneHour: "1時間", oneDay: "1日", oneWeek: "1週間", forever: "永久",
    encryptionLabel: "暗号化の強さ", none: "なし", noneHelp: "高速。運営者からも本文を読めます", standard: "標準", standardHelp: "X25519 + XChaCha20。推奨設定", strong: "強力", strongHelp: "X-Wing耐量子ハイブリッド暗号",
    passwordLabel: "RECOVERY PASSPHRASE", passwordHelp: "強力モードの秘密鍵をArgon2idで保護します。パスフレーズはサーバーへ送信されません。", importPasswordLabel: "PASSPHRASE（強力モードのみ）", passwordRequired: "12文字以上のパスフレーズを設定してください", wrongPassword: "パスフレーズが違うか、Recovery Keyが壊れています",
    noneWarning: "「なし」ではメール本文が平文で保存され、zero-accessではなくなります。", create: "この設定で Inbox を作る", import: "Recovery Key で既存Inboxを開く", restore: "Inbox を復元",
    identityTitle: "アカウントを作らない", identityText: "ユーザーテーブルを持たず、Inbox 同士も関連付けません。", storageTitle: "暗号文だけを保存", storageText: "標準・強力モードではraw MIME全体を入口で暗号化します。", retentionTitle: "残す期間を選べる", retentionText: "1時間から永久まで。期限後はメールとInboxを削除します。",
    saveRecovery: "Recovery Key を保管", recoveryHelp: "別端末で Inbox を開く唯一の鍵です。再発行はできません。", copyRecovery: "Recovery Key をコピー", saved: "安全な場所に保管しました", openInbox: "Inbox を開く", copyAddress: "アドレスをコピー", close: "閉じる",
    networkError: "通信に失敗しました", invalidRecovery: "Recovery Key の形式が正しくありません", brokenRecovery: "Recovery Key が壊れています", unsupportedEncryption: "未対応の暗号形式です", noSubject: "(件名なし)", unknownSender: "送信者不明", loading: "端末内で復号・解析しています...", encryptedMail: "暗号化メール / クリックして復号", empty: "まだメールはありません。このページを開いている間は15秒ごとに確認します。", messages: "件のメール", deleteMail: "このメールを削除", attachments: "添付ファイル", expires: "Inboxの有効期限", permanent: "永久", blockedImages: "プライバシー保護のため外部画像をブロックしました。",
  },
  en: {
    hero: "Your email belongs<br><i>only to you.</i>", lead: "Messages are encrypted the instant they arrive and decrypted only on this device. We do not have the key needed to read them.",
    addressLabel: "CUSTOM ADDRESS (OPTIONAL)", expiryLabel: "EXPIRY", oneHour: "1 hour", oneDay: "1 day", oneWeek: "1 week", forever: "Forever",
    encryptionLabel: "ENCRYPTION LEVEL", none: "None", noneHelp: "Fast. The operator can read messages", standard: "Standard", standardHelp: "X25519 + XChaCha20. Recommended", strong: "Strong", strongHelp: "X-Wing post-quantum hybrid encryption",
    passwordLabel: "RECOVERY PASSPHRASE", passwordHelp: "Protects the Strong-mode private key with Argon2id. The passphrase is never sent to the server.", importPasswordLabel: "PASSPHRASE (STRONG MODE ONLY)", passwordRequired: "Use a passphrase of at least 12 characters", wrongPassword: "The passphrase is incorrect or the Recovery Key is damaged",
    noneWarning: "With None, messages are stored in plaintext and this inbox is not zero-access.", create: "Create inbox with these settings", import: "Open an existing inbox with a Recovery Key", restore: "Restore inbox",
    identityTitle: "No account required", identityText: "There is no users table and inboxes are never linked together.", storageTitle: "Store ciphertext only", storageText: "Standard and Strong encrypt the complete raw MIME at ingress.", retentionTitle: "Choose retention", retentionText: "From one hour to forever. The inbox and mail are removed after expiry.",
    saveRecovery: "Save your Recovery Key", recoveryHelp: "This is the only way to open the inbox on another device. It cannot be reissued.", copyRecovery: "Copy Recovery Key", saved: "I saved it somewhere safe", openInbox: "Open inbox", copyAddress: "Copy address", close: "Close",
    networkError: "The request failed", invalidRecovery: "The Recovery Key format is invalid", brokenRecovery: "The Recovery Key is damaged", unsupportedEncryption: "Unsupported encryption format", noSubject: "(No subject)", unknownSender: "Unknown sender", loading: "Decrypting and parsing on this device...", encryptedMail: "Encrypted message / click to decrypt", empty: "No messages yet. This page checks every 15 seconds while open.", messages: "message(s)", deleteMail: "Delete this message", attachments: "Attachments", expires: "Inbox expires", permanent: "Forever", blockedImages: "External images were blocked to protect your privacy.",
  },
};

const t = (key) => translations[language][key] || key;

function applyLanguage() {
  document.documentElement.lang = language;
  document.querySelectorAll("[data-i18n]").forEach((element) => { element.textContent = t(element.dataset.i18n); });
  document.querySelectorAll("[data-i18n-html]").forEach((element) => { element.innerHTML = t(element.dataset.i18nHtml); });
  $("#language").textContent = language === "ja" ? "EN" : "日本語";
  $("#local-part").placeholder = language === "ja" ? "ランダム生成" : "randomly generated";
}

function base64url(bytes) {
  let binary = "";
  const value = new Uint8Array(bytes);
  for (let offset = 0; offset < value.length; offset += 0x8000) binary += String.fromCharCode(...value.subarray(offset, offset + 0x8000));
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function unbase64url(value) {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
}

async function api(path, options = {}) {
  const headers = { ...(options.body ? { "content-type": "application/json" } : {}), ...(options.headers || {}) };
  if (sessionToken) headers.authorization = `Bearer ${sessionToken}`;
  const response = await fetch(path, { ...options, headers });
  if (!response.ok) {
    const data = await response.json().catch(() => ({}));
    throw new Error(data.error || t("networkError"));
  }
  return response.status === 204 ? null : response.json();
}

async function makeCredentials(mode) {
  const auth = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const result = {
    encryptionMode: mode,
    authPrivateKey: await crypto.subtle.exportKey("jwk", auth.privateKey),
    authPublicKey: await crypto.subtle.exportKey("jwk", auth.publicKey),
  };
  if (mode === "standard") {
    const encryption = x25519.keygen();
    result.encryptionPrivateKey = { algorithm: "X25519", key: base64url(encryption.secretKey) };
    result.encryptionPublicKey = { algorithm: "X25519", key: base64url(encryption.publicKey) };
  } else if (mode === "strong") {
    const encryption = ml_kem768_x25519.keygen();
    result.encryptionPrivateKey = { algorithm: "XWING-MLKEM768-X25519", key: base64url(encryption.secretKey) };
    result.encryptionPublicKey = { algorithm: "XWING-MLKEM768-X25519", key: base64url(encryption.publicKey) };
  }
  return result;
}

async function deriveRecoveryKey(password, salt, parameters = {}) {
  return argon2id({
    password,
    salt,
    parallelism: parameters.parallelism || 1,
    iterations: parameters.iterations || 3,
    memorySize: parameters.memorySize || 65536,
    hashLength: 32,
    outputType: "binary",
  });
}

async function exportRecovery(value, password) {
  if (value.encryptionMode !== "strong") return `md1_${base64url(encoder.encode(JSON.stringify(value)))}`;
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const nonce = crypto.getRandomValues(new Uint8Array(24));
  const parameters = { memorySize: 65536, iterations: 3, parallelism: 1 };
  const key = await deriveRecoveryKey(password, salt, parameters);
  const ciphertext = xchacha20poly1305(key, nonce, encoder.encode("mailday-recovery:argon2id:v2"))
    .encrypt(encoder.encode(JSON.stringify(value)));
  key.fill(0);
  return `md2_${base64url(encoder.encode(JSON.stringify({
    version: 2,
    kdf: { name: "argon2id", ...parameters, salt: base64url(salt) },
    nonce: base64url(nonce),
    ciphertext: base64url(ciphertext),
  })))}`;
}

async function importRecovery(value, password) {
  let parsed;
  if (value.startsWith("md1_")) {
    parsed = JSON.parse(decoder.decode(unbase64url(value.slice(4))));
  } else if (value.startsWith("md2_")) {
    try {
      const envelope = JSON.parse(decoder.decode(unbase64url(value.slice(4))));
      if (envelope.version !== 2 || envelope.kdf?.name !== "argon2id") throw new Error();
      const key = await deriveRecoveryKey(password, unbase64url(envelope.kdf.salt), envelope.kdf);
      const plaintext = xchacha20poly1305(key, unbase64url(envelope.nonce), encoder.encode("mailday-recovery:argon2id:v2"))
        .decrypt(unbase64url(envelope.ciphertext));
      key.fill(0);
      parsed = JSON.parse(decoder.decode(plaintext));
    } catch {
      throw new Error(t("wrongPassword"));
    }
  } else {
    throw new Error(t("invalidRecovery"));
  }
  if (!parsed.address || !parsed.authPrivateKey) throw new Error(t("brokenRecovery"));
  parsed.encryptionMode ||= parsed.encryptionPrivateKey?.crv === "P-384" ? "strong" : "standard";
  if (parsed.encryptionMode !== "none" && !parsed.encryptionPrivateKey) throw new Error(t("brokenRecovery"));
  return parsed;
}

async function authenticate() {
  const issued = await api("/api/auth/challenge", { method: "POST", body: JSON.stringify({ address: credentials.address }) });
  const privateKey = await crypto.subtle.importKey("jwk", credentials.authPrivateKey, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const signature = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, privateKey, encoder.encode(issued.challenge));
  const verified = await api("/api/auth/verify", { method: "POST", body: JSON.stringify({ challengeId: issued.challengeId, challenge: issued.challenge, signature: base64url(signature) }) });
  sessionToken = verified.token;
}

async function createInbox(event) {
  event.preventDefault();
  $("#create").disabled = true;
  try {
    const encryptionMode = new FormData(event.currentTarget).get("encryption");
    const recoveryPassword = $("#strong-password").value;
    if (encryptionMode === "strong" && recoveryPassword.length < 12) throw new Error(t("passwordRequired"));
    credentials = await makeCredentials(encryptionMode);
    const created = await api("/api/mailboxes", {
      method: "POST",
      body: JSON.stringify({
        localPart: $("#local-part").value,
        expiresIn: $("#expires-in").value,
        encryptionMode,
        authPublicKey: credentials.authPublicKey,
        encryptionPublicKey: credentials.encryptionPublicKey,
      }),
    });
    Object.assign(credentials, created);
    $("#new-recovery").value = await exportRecovery(credentials, recoveryPassword);
    $("#strong-password").value = "";
    $("#recovery-panel").classList.remove("hidden");
  } catch (error) {
    alert(error.message);
  } finally {
    $("#create").disabled = false;
  }
}

async function openInbox() {
  try {
    await authenticate();
    $("#landing").classList.add("hidden");
    $("#recovery-panel").classList.add("hidden");
    $("#inbox").classList.remove("hidden");
    await refresh();
  } catch (error) {
    alert(error.message);
  }
}

async function decryptEnvelope(envelope) {
  if (envelope.version === 2) {
    const privateKey = credentials.encryptionPrivateKey;
    const encapsulation = unbase64url(envelope.encapsulation);
    let sharedSecret;
    if (envelope.algorithm === "XWING-MLKEM768-X25519+XCHACHA20POLY1305" && privateKey?.algorithm === "XWING-MLKEM768-X25519") {
      sharedSecret = ml_kem768_x25519.decapsulate(encapsulation, unbase64url(privateKey.key));
    } else if (envelope.algorithm === "X25519+XCHACHA20POLY1305" && privateKey?.algorithm === "X25519") {
      sharedSecret = x25519.getSharedSecret(unbase64url(privateKey.key), encapsulation);
    } else {
      throw new Error(t("unsupportedEncryption"));
    }
    const nonce = unbase64url(envelope.nonce);
    const contentKey = hkdf(sha512, sharedSecret, nonce, encoder.encode(`mailday:${envelope.algorithm}:v1`), 32);
    const plaintext = xchacha20poly1305(contentKey, nonce, encoder.encode(`mailday-envelope:${envelope.algorithm}:v2`))
      .decrypt(unbase64url(envelope.ciphertext));
    sharedSecret.fill(0);
    contentKey.fill(0);
    return plaintext;
  }
  if (envelope.version !== 1) throw new Error(t("unsupportedEncryption"));
  if (envelope.algorithm === "NONE") return unbase64url(envelope.raw);
  const curve = envelope.algorithm === "P-384/ECDH+A256GCM" ? "P-384" : envelope.algorithm === "P-256/ECDH+A256GCM" ? "P-256" : null;
  if (!curve || !credentials.encryptionPrivateKey) throw new Error(t("unsupportedEncryption"));
  const privateKey = await crypto.subtle.importKey("jwk", credentials.encryptionPrivateKey, { name: "ECDH", namedCurve: curve }, false, ["deriveKey"]);
  const ephemeralKey = await crypto.subtle.importKey("jwk", envelope.ephemeralPublicKey, { name: "ECDH", namedCurve: curve }, false, []);
  const wrappingKey = await crypto.subtle.deriveKey({ name: "ECDH", public: ephemeralKey }, privateKey, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
  const rawContentKey = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unbase64url(envelope.wrappedKeyIv) }, wrappingKey, unbase64url(envelope.wrappedKey));
  const contentKey = await crypto.subtle.importKey("raw", rawContentKey, "AES-GCM", false, ["decrypt"]);
  const raw = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unbase64url(envelope.contentIv) }, contentKey, unbase64url(envelope.ciphertext));
  return new Uint8Array(raw);
}

function renderMessage(email, body) {
  body.replaceChildren();
  const sender = document.createElement("p");
  sender.className = "mail-meta";
  sender.textContent = `From: ${email.from?.name ? `${email.from.name} <${email.from.address}>` : email.from?.address || t("unknownSender")}`;
  body.append(sender);

  let blockedImages = false;
  if (email.html) {
    const content = document.createElement("div");
    content.className = "mail-content";
    content.innerHTML = DOMPurify.sanitize(email.html, { FORBID_TAGS: ["style", "script", "iframe", "object", "embed", "form"], FORBID_ATTR: ["style", "srcset"] });
    content.querySelectorAll("img, source").forEach((image) => {
      const source = image.getAttribute("src");
      if (source?.startsWith("cid:")) {
        const contentId = source.slice(4).replace(/^<|>$/g, "");
        const attachment = email.attachments?.find((item) => item.contentId?.replace(/^<|>$/g, "") === contentId);
        if (attachment) image.setAttribute("src", URL.createObjectURL(new Blob([attachment.content], { type: attachment.mimeType })));
        else image.removeAttribute("src");
      } else if (source && !source.startsWith("data:")) {
        image.removeAttribute("src");
        blockedImages = true;
      }
    });
    content.querySelectorAll("a").forEach((link) => { link.target = "_blank"; link.rel = "noopener noreferrer"; });
    body.append(content);
  } else {
    const content = document.createElement("pre");
    content.textContent = email.text || "";
    body.append(content);
  }
  if (blockedImages) {
    const notice = document.createElement("p");
    notice.className = "mail-meta";
    notice.textContent = t("blockedImages");
    body.append(notice);
  }

  if (email.attachments?.length) {
    const title = document.createElement("p");
    title.className = "mail-meta";
    title.textContent = `${t("attachments")} (${email.attachments.length})`;
    const attachments = document.createElement("div");
    attachments.className = "attachments";
    email.attachments.forEach((attachment, index) => {
      const link = document.createElement("a");
      link.className = "attachment";
      link.download = attachment.filename || `attachment-${index + 1}`;
      link.href = URL.createObjectURL(new Blob([attachment.content], { type: attachment.mimeType || "application/octet-stream" }));
      link.textContent = `${link.download} (${Math.ceil(attachment.content.byteLength / 1024)} KB)`;
      attachments.append(link);
    });
    body.append(title, attachments);
  }
}

async function refresh() {
  const data = await api("/api/messages");
  $("#address").textContent = data.address;
  const permanent = data.expiresAt >= 253_402_300_000_000;
  $("#expiry").textContent = `${t("expires")}: ${permanent ? t("permanent") : new Date(data.expiresAt).toLocaleString(language === "ja" ? "ja-JP" : "en-US")}`;
  $("#messages").replaceChildren();
  if (!data.messages.length) {
    $("#status").textContent = t("empty");
    return;
  }
  $("#status").textContent = `${data.messages.length} ${t("messages")}`;
  for (const item of data.messages) {
    const details = document.createElement("details");
    details.className = "message";
    const summary = document.createElement("summary");
    const label = document.createElement("span");
    label.textContent = t("encryptedMail");
    const time = document.createElement("time");
    time.textContent = new Date(item.received_at).toLocaleString(language === "ja" ? "ja-JP" : "en-US");
    const size = document.createElement("small");
    size.textContent = `${Math.ceil(item.size / 1024)} KB`;
    summary.append(label, time, size);
    const body = document.createElement("div");
    body.className = "message-body";
    body.textContent = t("loading");
    details.append(summary, body);
    details.addEventListener("toggle", async () => {
      if (!details.open || details.dataset.loaded) return;
      details.dataset.loaded = "true";
      try {
        const envelope = await api(`/api/messages/${item.message_id}`);
        const raw = await decryptEnvelope(envelope);
        const email = await PostalMime.parse(raw);
        label.textContent = email.subject || t("noSubject");
        renderMessage(email, body);
        const remove = document.createElement("button");
        remove.textContent = t("deleteMail");
        remove.addEventListener("click", async () => { await api(`/api/messages/${item.message_id}`, { method: "DELETE" }); details.remove(); });
        body.append(remove);
      } catch (error) {
        body.textContent = error.message;
      }
    });
    $("#messages").append(details);
  }
}

$("#create-form").addEventListener("submit", createInbox);
$("#show-import").addEventListener("click", () => $("#import-form").classList.toggle("hidden"));
$("#saved-key").addEventListener("change", (event) => { $("#open-created").disabled = !event.target.checked; });
$("#open-created").addEventListener("click", openInbox);
$("#copy-recovery").addEventListener("click", () => navigator.clipboard.writeText($("#new-recovery").value));
$("#copy-address").addEventListener("click", () => navigator.clipboard.writeText(credentials.address));
$("#import-form").addEventListener("submit", async (event) => { event.preventDefault(); try { credentials = await importRecovery($("#recovery").value.trim(), $("#recovery-password").value); $("#recovery-password").value = ""; await openInbox(); } catch (error) { alert(error.message); } });
$("#lock").addEventListener("click", () => { credentials = null; sessionToken = null; location.reload(); });
$("#language").addEventListener("click", () => { language = language === "ja" ? "en" : "ja"; localStorage.setItem("mailday-language", language); applyLanguage(); if (sessionToken) refresh().catch(() => {}); });
document.querySelectorAll('input[name="encryption"]').forEach((input) => input.addEventListener("change", () => {
  if (!input.checked) return;
  $("#encryption-warning").classList.toggle("hidden", input.value !== "none");
  $("#strong-password-field").classList.toggle("hidden", input.value !== "strong");
  $("#strong-password").required = input.value === "strong";
}));
setInterval(() => { if (sessionToken && !document.hidden) refresh().catch(() => {}); }, 15_000);
applyLanguage();
