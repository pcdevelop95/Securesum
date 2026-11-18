// The MPC protocol steps, shared by the web app and the automated tests.
//join, shares bhejna, apne shares kholkar partial sum bhejna
import {
  decryptText, encryptText, generateKeyPair, importPrivateKey, importPublicKey, keysMatch,
} from "./crypto.js";
import { parseScaled, splitSecret, sumMod } from "./mpc.js";

function describe(detail) {
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) return "Please check the values you entered.";
  return "Something went wrong.";
}

export function makeApi(baseUrl, getToken) {
  return async function api(method, path, body) {
    const headers = {};
    const token = getToken();
    if (token) headers.Authorization = "Bearer " + token;
    if (body !== undefined) headers["Content-Type"] = "application/json";
    let res;
    try {
      res = await fetch(baseUrl + path, {
        method, headers, body: body !== undefined ? JSON.stringify(body) : undefined,
      });
    } catch (e) {
      const err = new Error("Cannot reach the server. Check your connection.");
      err.status = 0;
      throw err;
    }
    let data = null;
    try { data = await res.json(); } catch (e) { /* no body */ }
    if (!res.ok) {
      const err = new Error(data && data.detail ? describe(data.detail) : `Request failed (${res.status})`);
      err.status = res.status;
      err.code = data && data.code ? data.code : undefined;
      throw err;
    }
    return data;
  };
}

// keyStore: { get(userId, sessionId) -> {privateJwk, publicKeyB64} | null, set(userId, sessionId, entry) }

// Step 1 (Setup): create a key pair in this browser, give the server only the public half.
export async function joinWithNewKey(api, keyStore, userId, code) {
  const { publicKeyB64, privateJwk } = await generateKeyPair();
  const session = await api("POST", `/api/invite/${encodeURIComponent(code)}/join`, {
    public_key: publicKeyB64,
  });
  await keyStore.set(userId, session.id, { privateJwk, publicKeyB64 });
  return session;
}

// Step 2 (Input sharing): split the value, encrypt share j for party j, upload ciphertexts.
export async function sendShares(api, keyStore, userId, session, valueText) {
  if (!session.me) throw new Error("You are not a party in this session.");
  const n = session.n_parties;
  const p = BigInt(session.modulus);
  const value = parseScaled(valueText, session.decimals);

  const mine = await keyStore.get(userId, session.id);
  const listed = session.participants.find((x) => x.idx === session.me.idx);
  if (!mine || !listed || listed.public_key !== mine.publicKeyB64) {
    throw new Error(
      "The key the server lists for you does not match the key in this browser. " +
      "Do not continue: restore your key backup or contact the session creator."
    );
  }
  const ordered = [...session.participants].sort((a, b) => a.idx - b.idx);
  if (ordered.length !== n) throw new Error("Not all parties have joined yet.");

  const shares = splitSecret(value, n, p);
  const payload = [];
  for (let j = 0; j < n; j++) {
    const key = await importPublicKey(ordered[j].public_key);
    payload.push({ to_idx: ordered[j].idx, ciphertext: await encryptText(key, shares[j].toString()) });
  }
  const updated = await api("POST", `/api/sessions/${session.id}/shares`, { shares: payload });
  return { session: updated, shares: shares.map((s) => s.toString()), value: value.toString() };
}

// Steps 3 + 4 (Local computation, Share exchange): decrypt my n shares, add mod p, publish only the sum.
export async function sendPartial(api, keyStore, userId, session) {
  const mine = await keyStore.get(userId, session.id);
  if (!mine) throw new Error("KEY_MISSING");
  const priv = await importPrivateKey(mine.privateJwk);
  const p = BigInt(session.modulus);
  const { shares } = await api("GET", `/api/sessions/${session.id}/my-shares`);
  if (shares.length !== session.n_parties) throw new Error("Some shares are missing on the server.");
  const parts = [];
  for (const s of shares) {
    let text;
    try { text = await decryptText(priv, s.ciphertext); }
    catch (e) { throw new Error(`Could not decrypt the share from party ${s.from_idx}.`); }
    if (!/^\d{1,20}$/.test(text)) throw new Error(`The share from party ${s.from_idx} is corrupted.`);
    parts.push(BigInt(text));
  }
  const partial = sumMod(parts, p);
  return api("POST", `/api/sessions/${session.id}/partial`, { partial: partial.toString() });
}

// Key backup helpers (used by the UI).
export function makeBackup(userId, sessionId, entry) {
  return JSON.stringify({ app: "SecureSum", version: 1, sessionId, ...entry }, null, 2);
}

export async function parseBackup(text, session) {
  let data;
  try { data = JSON.parse(text); } catch (e) { throw new Error("That file is not a valid key backup."); }
  if (!data || data.app !== "SecureSum" || !data.privateJwk || !data.publicKeyB64) {
    throw new Error("That file is not a valid key backup.");
  }
  const listed = session.participants.find((x) => x.idx === (session.me && session.me.idx));
  if (!listed || listed.public_key !== data.publicKeyB64) {
    throw new Error("This backup belongs to a different session or account.");
  }
  if (!(await keysMatch(data.publicKeyB64, data.privateJwk))) {
    throw new Error("The backup file is damaged (keys do not match).");
  }
  return { privateJwk: data.privateJwk, publicKeyB64: data.publicKeyB64 };
}
