// Browser-side cryptography (WebCrypto). Private keys never leave the browser.
// share ko lock ya unlock karna, session ko join karna, aur shares ko send karna.
const hasCrypto = typeof globalThis.crypto !== "undefined" && globalThis.crypto.subtle;

export function requireCrypto() {
  if (!hasCrypto) {
    throw new Error(
      "This browser blocks secure cryptography on this address. Open the site over " +
      "HTTPS (or http://localhost) and try again."
    );
  }
  return globalThis.crypto.subtle;
}

const enc = new TextEncoder();
const dec = new TextDecoder();

export function bytesToB64(buf) {
  const b = new Uint8Array(buf);
  let s = "";
  for (let i = 0; i < b.length; i += 0x8000) {
    s += String.fromCharCode.apply(null, b.subarray(i, i + 0x8000));
  }
  return btoa(s);
}

export function b64ToBytes(str) {
  const s = atob(str);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

const KEY_PARAMS = {
  name: "RSA-OAEP",
  modulusLength: 2048,
  publicExponent: new Uint8Array([1, 0, 1]),
  hash: "SHA-256",
};
const IMPORT_PARAMS = { name: "RSA-OAEP", hash: "SHA-256" };

export async function generateKeyPair() {
  const subtle = requireCrypto();
  const kp = await subtle.generateKey(KEY_PARAMS, true, ["encrypt", "decrypt"]);
  const spki = await subtle.exportKey("spki", kp.publicKey);
  const privateJwk = await subtle.exportKey("jwk", kp.privateKey);
  return { publicKeyB64: bytesToB64(spki), privateJwk };
}

export async function importPublicKey(b64) {
  return requireCrypto().importKey("spki", b64ToBytes(b64), IMPORT_PARAMS, false, ["encrypt"]);
}

export async function importPrivateKey(jwk) {
  return requireCrypto().importKey("jwk", jwk, IMPORT_PARAMS, false, ["decrypt"]);
}

export async function encryptText(publicKey, text) {
  const ct = await requireCrypto().encrypt({ name: "RSA-OAEP" }, publicKey, enc.encode(text));
  return bytesToB64(ct);
}

export async function decryptText(privateKey, b64) {
  const pt = await requireCrypto().decrypt({ name: "RSA-OAEP" }, privateKey, b64ToBytes(b64));
  return dec.decode(pt);
}

// Short human-comparable fingerprint of a public key, e.g. "A1B2 C3D4 E5F6 0718 293A".
export async function fingerprint(publicKeyB64) {
  const h = new Uint8Array(await requireCrypto().digest("SHA-256", b64ToBytes(publicKeyB64)));
  const hex = Array.from(h.slice(0, 10), (x) => x.toString(16).padStart(2, "0")).join("").toUpperCase();
  return hex.match(/.{4}/g).join(" ");
}

// True if the private key (JWK) really belongs to the public key (base64 SPKI).
export async function keysMatch(publicKeyB64, privateJwk) {
  try {
    const pub = await importPublicKey(publicKeyB64);
    const priv = await importPrivateKey(privateJwk);
    const probe = "probe-" + Math.random().toString(36).slice(2);
    return (await decryptText(priv, await encryptText(pub, probe))) === probe;
  } catch (e) {
    return false;
  }
}
