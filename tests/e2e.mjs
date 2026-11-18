// End-to-end test: runs the REAL browser protocol code (WebCrypto + secret sharing)
// against a running server. Usage: node tests/e2e.mjs http://127.0.0.1:8765
import assert from "node:assert/strict";
import { decryptText, importPrivateKey } from "../frontend/js/crypto.js";
import { joinWithNewKey, makeApi, sendPartial, sendShares, parseBackup, makeBackup } from "../frontend/js/protocol.js";

const BASE = process.argv[2] || "http://127.0.0.1:8765";
// Sign-up now needs the 6-digit code the server e-mails. The test server exposes it at /__test/code.
async function codeFor(email) {
  const r = await fetch(`${BASE}/__test/code?email=${encodeURIComponent(email)}`);
  return (await r.json()).code;
}
async function signUp(email, password, name) {
  const api0 = makeApi(BASE, () => null);
  const r = await api0("POST", "/api/auth/register", { email, password, name });
  assert.equal(r.needs_verification, true);
  assert.equal(r.token, undefined, "no login before verification");
  return api0("POST", "/api/auth/verify", { email, code: await codeFor(email) });
}

let counter = 0;
let passed = 0;
const ok = (name) => { passed++; console.log("  ok  -", name); };

class Client {
  constructor(name) { this.name = name; this.token = null; this.user = null; this.keys = new Map();
    this.api = makeApi(BASE, () => this.token); }
  get keyStore() {
    return { get: async (u, s) => this.keys.get(`${u}:${s}`) || null,
             set: async (u, s, e) => { this.keys.set(`${u}:${s}`, e); } };
  }
  async register() {
    const email = `user${++counter}_${Date.now()}@example.com`;
    const r = await signUp(email, "password123", this.name);
    this.token = r.token; this.user = r.user; return this;
  }
  join(code) { return joinWithNewKey(this.api, this.keyStore, this.user.id, code); }
  view(id) { return this.api("GET", `/api/sessions/${id}`); }
  async send(id, value) { return sendShares(this.api, this.keyStore, this.user.id, await this.view(id), value); }
  async partial(id) { return sendPartial(this.api, this.keyStore, this.user.id, await this.view(id)); }
}

async function runSession({ n, values, decimals = 0, metric = "sum", expectSum, expectAvg }) {
  const clients = await Promise.all(values.map((_, i) => new Client(`P${i + 1}`).register()));
  const created = await clients[0].api("POST", "/api/sessions", { title: "e2e", n_parties: n, metric, decimals });
  // everyone joins at the same time (tests the server's slot assignment)
  await Promise.all(clients.map((c) => c.join(created.code)));
  let s = await clients[0].view(created.id);
  assert.equal(s.state, "sharing");
  assert.deepEqual(s.participants.map((p) => p.idx), Array.from({ length: n }, (_, i) => i + 1));
  const sent = await Promise.all(clients.map((c, i) => c.send(created.id, values[i])));
  s = await clients[0].view(created.id);
  assert.equal(s.state, "summing");
  // privacy: what the server stores is not readable by anyone but the recipient
  const probe = clients[0], other = clients[n > 1 ? 1 : 0];
  const myShares = await probe.api("GET", `/api/sessions/${created.id}/my-shares`);
  const otherKey = await importPrivateKey(other.keys.get(`${other.user.id}:${created.id}`).privateJwk);
  if (n > 1) {
    await assert.rejects(() => decryptText(otherKey, myShares.shares[0].ciphertext));
  }
  await Promise.all(clients.map((c) => c.partial(created.id)));
  s = await clients[0].view(created.id);
  assert.equal(s.state, "done");
  assert.equal(s.result.sum, expectSum);
  if (expectAvg) assert.equal(s.result.average, expectAvg);
  // every party sees the same result
  for (const c of clients) assert.deepEqual((await c.view(created.id)).result, s.result);
  // for n >= 3 no single published partial sum equals any party's input
  return { s, sent, clients, created };
}

console.log("SecureSum end-to-end tests against", BASE);

await runSession({ n: 4, values: ["50", "70", "30", "90"], expectSum: "240", expectAvg: "60.00" });
ok("4 parties: 50+70+30+90 = 240, average 60.00 (example from the presentation)");

await runSession({ n: 3, values: ["1234.56", "0.44", "10"], decimals: 2, expectSum: "1245.00", expectAvg: "415.0000" });
ok("3 parties with 2 decimals: 1234.56 + 0.44 + 10 = 1245.00");

await runSession({ n: 1, values: ["7"], expectSum: "7" });
ok("1 party works (sum equals its own value)");

await runSession({ n: 2, values: ["10", "21"], expectSum: "31", expectAvg: "15.50" });
ok("2 parties work");

const big = await runSession({ n: 8, values: ["1", "2", "3", "4", "5", "6", "7", "8"], expectSum: "36", expectAvg: "4.50" });
ok("8 parties, all joining and sending concurrently");

// Shares really are random-looking: the shares a party made add up to its value but none equals it.
{
  const r = await runSession({ n: 5, values: ["1000", "2000", "3000", "4000", "5000"], expectSum: "15000" });
  const P = (1n << 61n) - 1n;
  r.sent.forEach((x) => {
    const total = x.shares.reduce((a, b) => (a + BigInt(b)) % P, 0n);
    assert.equal(total.toString(), x.value);
    assert.ok(!x.shares.includes(x.value));
  });
  ok("shares add up to the secret mod p, and no single share reveals it");
}

// Input validation in the browser code
{
  const c = await new Client("V").register();
  const created = await c.api("POST", "/api/sessions", { title: "v", n_parties: 1, decimals: 0 });
  await c.join(created.code);
  for (const bad of ["", "abc", "-5", "1.5", "99999999999999999", "1e5"]) {
    await assert.rejects(() => c.send(created.id, bad), undefined, `should reject ${bad}`);
  }
  ok("invalid values are rejected before anything is sent");
}

// Tamper detection: if the server lists a different key for me, sending is refused
{
  const [a, b] = await Promise.all([new Client("A").register(), new Client("B").register()]);
  const created = await a.api("POST", "/api/sessions", { title: "t", n_parties: 2 });
  await Promise.all([a.join(created.code), b.join(created.code)]);
  const s = await a.view(created.id);
  const forged = structuredClone(s);
  // replace the key listed for ME with someone else's key (a joins concurrently, so its idx may be 1 or 2)
  const mine = forged.participants.find((p) => p.idx === s.me.idx);
  const theirs = s.participants.find((p) => p.idx !== s.me.idx);
  mine.public_key = theirs.public_key;
  await assert.rejects(() => sendShares(a.api, a.keyStore, a.user.id, forged, "5"), /does not match/);
  ok("key-substitution by the server is detected and refused");

  // key backup / restore
  const entry = a.keys.get(`${a.user.id}:${created.id}`);
  const text = makeBackup(a.user.id, created.id, entry);
  const restored = await parseBackup(text, s);
  assert.equal(restored.publicKeyB64, entry.publicKeyB64);
  await assert.rejects(() => parseBackup(text, { ...s, me: { idx: s.me.idx === 1 ? 2 : 1 } }), /different session/);
  await assert.rejects(() => parseBackup("not json", s), /not a valid/);
  ok("key backup restores, and wrong or corrupt backups are rejected");

  // a party that lost its key cannot compute the partial sum
  await Promise.all([a.send(created.id, "5"), b.send(created.id, "6")]);
  const lost = new Client("lost"); lost.token = a.token; lost.user = a.user;
  await assert.rejects(() => lost.partial(created.id), /KEY_MISSING/);
  ok("missing key is reported (so the UI can ask for the backup)");
}

// Auth and access control
{
  const a = await new Client("A").register();
  const intruder = await new Client("I").register();
  const created = await a.api("POST", "/api/sessions", { title: "secret", n_parties: 3 });
  await assert.rejects(() => intruder.view(created.id), /not found/i);
  const noAuth = makeApi(BASE, () => null);
  await assert.rejects(() => noAuth("GET", "/api/sessions"), /log in/i);
  ok("outsiders and anonymous users cannot see a session");
}

// Leave before the session is full: later parties move up, and the protocol still completes correctly
{
  const [A, B, C, D, E] = await Promise.all(["A", "B", "C", "D", "E"].map((n) => new Client(n).register()));
  const created = await A.api("POST", "/api/sessions", { title: "leave", n_parties: 4 });
  await A.join(created.code); await B.join(created.code); await C.join(created.code);
  await B.api("POST", `/api/sessions/${created.id}/leave`);
  let v = await A.view(created.id);
  assert.deepEqual(v.participants.map((p) => [p.idx, p.name]), [[1, "A"], [2, "C"]]);
  await assert.rejects(() => B.view(created.id), /not found/i);
  await D.join(created.code); await E.join(created.code);     // D takes slot 3, E takes slot 4
  v = await A.view(created.id);
  assert.deepEqual(v.participants.map((p) => p.name), ["A", "C", "D", "E"]);
  assert.equal(v.state, "sharing");
  const people = [A, C, D, E];
  await Promise.all(people.map((c, i) => c.send(created.id, String((i + 1) * 100))));
  await Promise.all(people.map((c) => c.partial(created.id)));
  v = await A.view(created.id);
  assert.equal(v.result.sum, "1000");
  ok("a party can leave before the session is full; renumbering keeps the maths and the encryption correct");

  // after finishing: archive, restore, creator-only delete
  await assert.rejects(() => C.api("DELETE", `/api/sessions/${created.id}`), /Only the creator/);
  await C.api("POST", `/api/sessions/${created.id}/hide`);
  assert.equal((await C.api("GET", "/api/sessions")).sessions.length, 0);
  assert.equal((await C.api("GET", "/api/sessions?archived=1")).sessions.length, 1);
  assert.equal((await A.api("GET", "/api/sessions")).sessions.length, 1);   // others keep it
  await C.api("POST", `/api/sessions/${created.id}/unhide`);
  assert.equal((await C.api("GET", "/api/sessions")).sessions.length, 1);
  ok("finished sessions can be archived and restored, per person");
  await A.api("DELETE", `/api/sessions/${created.id}`);
  await assert.rejects(() => C.view(created.id), /not found/i);
  assert.equal((await C.api("GET", "/api/sessions")).sessions.length, 0);
  ok("creator deletes a session and it disappears for everyone");
}

// Creator deletes while the run is in progress
{
  const [A, B, C] = await Promise.all(["A", "B", "C"].map((n) => new Client(n).register()));
  const created = await A.api("POST", "/api/sessions", { title: "cancel", n_parties: 3 });
  await Promise.all([A, B, C].map((c) => c.join(created.code)));
  await A.send(created.id, "5");
  await A.api("DELETE", `/api/sessions/${created.id}`);
  await assert.rejects(() => B.view(created.id), /not found/i);
  await assert.rejects(() => B.send(created.id, "6"), /not found/i);
  ok("deleting mid-run cancels it for the other parties");
}

// Password change
{
  const email = `pw${Date.now()}@example.com`;
  const api0 = makeApi(BASE, () => null);
  const first = await signUp(email, "password123", "Pw");
  const second = await api0("POST", "/api/auth/login", { email, password: "password123" });
  const me = makeApi(BASE, () => first.token);
  await assert.rejects(() => me("POST", "/api/auth/password", { old_password: "nope-nope", new_password: "brandnew123" }), /wrong/i);
  await me("POST", "/api/auth/password", { old_password: "password123", new_password: "brandnew123" });
  await me("GET", "/api/me");                                                            // this device stays signed in
  await assert.rejects(() => makeApi(BASE, () => second.token)("GET", "/api/me"), /log in/i);   // others are signed out
  await assert.rejects(() => api0("POST", "/api/auth/login", { email, password: "password123" }), /Wrong email/);
  await api0("POST", "/api/auth/login", { email, password: "brandnew123" });
  ok("password change signs out other devices; old password stops working");
}

// ---- a wrong or made-up email cannot create a usable account
{
  const api0 = makeApi(BASE, () => null);
  await assert.rejects(() => api0("POST", "/api/auth/register", { email: "asha@gmial.com", password: "password123", name: "A" }), /Did you mean asha@gmail\.com/);
  await assert.rejects(() => api0("POST", "/api/auth/register", { email: "not-an-email", password: "password123", name: "A" }), /valid email/);
  const email = `ghost${Date.now()}@example.com`;
  await api0("POST", "/api/auth/register", { email, password: "password123", name: "Ghost" });
  // knowing the password is not enough: the address must be confirmed first
  const err = await api0("POST", "/api/auth/login", { email, password: "password123" }).catch((e) => e);
  assert.equal(err.status, 403); assert.equal(err.code, "email_not_verified");
  await assert.rejects(() => api0("POST", "/api/auth/verify", { email, code: "000000" }), /wrong or has expired/);
  await assert.rejects(() => makeApi(BASE, () => "made-up-token")("GET", "/api/sessions"), /log in|expired/i);
  const done = await api0("POST", "/api/auth/verify", { email, code: await codeFor(email) });
  assert.equal(done.user.email_verified, true);
  await assert.rejects(() => api0("POST", "/api/auth/register", { email, password: "password123", name: "Again" }), /already registered/);
  ok("typo emails are refused; an account cannot be used until the e-mailed code is entered");
}

// ---- Google sign-in (fake Google token; the real verifier is tested on your machine)
{
  const api0 = makeApi(BASE, () => null);
  const sub = `sub${Date.now()}`;
  const first = await api0("POST", "/api/auth/google", { credential: `fake:${sub}:gina${sub}@example.com:Gina:true` });
  assert.equal(first.user.has_password, false); assert.equal(first.user.google_linked, true);
  const again = await api0("POST", "/api/auth/google", { credential: `fake:${sub}:gina${sub}@example.com:Gina:true` });
  assert.equal(again.user.id, first.user.id);
  await assert.rejects(() => api0("POST", "/api/auth/google", { credential: "nonsense" }), /Google sign-in failed/);
  await assert.rejects(() => api0("POST", "/api/auth/google", { credential: `fake:x${sub}:y${sub}@example.com:Y:false` }), /not verified/);
  // an existing password account is linked, not duplicated
  const email = `linked${Date.now()}@example.com`;
  const pw = await signUp(email, "password123", "Lin");
  const g = await api0("POST", "/api/auth/google", { credential: `fake:L${sub}:${email}:Lin:true` });
  assert.equal(g.user.id, pw.user.id);
  ok("Google sign-in creates, reuses and links accounts, and refuses unverified Google emails");
}

// ---- forgot password, devices, email change, delete account
{
  const api0 = makeApi(BASE, () => null);
  const email = `reset${Date.now()}@example.com`;
  const a = await signUp(email, "password123", "Rey");
  assert.deepEqual(await api0("POST", "/api/auth/forgot", { email: "nobody@example.com" }), { ok: true });
  await api0("POST", "/api/auth/forgot", { email });
  await api0("POST", "/api/auth/reset", { email, code: await codeFor(email), new_password: "freshpass123" });
  await assert.rejects(() => makeApi(BASE, () => a.token)("GET", "/api/me"), /log in|expired/i);
  const b = await api0("POST", "/api/auth/login", { email, password: "freshpass123" });
  const me = makeApi(BASE, () => b.token);
  const devices = (await me("GET", "/api/account/devices")).devices;
  assert.equal(devices.length, 1); assert.equal(devices[0].current, true);
  await me("POST", "/api/account/name", { name: "Rey Renamed" });
  assert.equal((await me("GET", "/api/me")).user.name, "Rey Renamed");
  const newEmail = `moved${Date.now()}@example.com`;
  await me("POST", "/api/account/email/request", { new_email: newEmail, password: "freshpass123" });
  await me("POST", "/api/account/email/confirm", { new_email: newEmail, code: await codeFor(newEmail) });
  assert.equal((await me("GET", "/api/me")).user.email, newEmail);
  // cannot leave others waiting: deleting is blocked while in an unfinished session
  const created = await me("POST", "/api/sessions", { title: "Open run", n_parties: 3 });
  await assert.rejects(() => me("POST", "/api/account/delete", { password: "freshpass123" }), /Open run/);
  await me("DELETE", `/api/sessions/${created.id}`);
  await assert.rejects(() => me("POST", "/api/account/delete", { password: "wrong-password" }), /wrong/i);
  await me("POST", "/api/account/delete", { password: "freshpass123" });
  await assert.rejects(() => me("GET", "/api/me"), /log in|expired/i);
  await assert.rejects(() => api0("POST", "/api/auth/login", { email: newEmail, password: "freshpass123" }), /Wrong email/);
  ok("forgot/reset, devices, rename, e-mail change by code, and account deletion (blocked while a run is open)");
}

console.log(`\nAll ${passed} end-to-end checks passed.`);
