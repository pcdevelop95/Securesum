// UI smoke test: runs the real frontend/js/app.js against a tiny fake DOM and a real server.
// Usage: node tests/ui_smoke.mjs http://127.0.0.1:8765
import assert from "node:assert/strict";

const BASE = process.argv[2] || "http://127.0.0.1:8765";

// ---------------- minimal fake DOM ----------------
class TextNode { constructor(t) { this.nodeType = 3; this.data = String(t); } get textContent() { return this.data; } }
class El {
  constructor(tag) { this.nodeType = 1; this.tag = tag; this.attrs = {}; this.children = []; this.listeners = {}; this.className = ""; this.value = ""; this.id = ""; }
  setAttribute(k, v) { this.attrs[k] = String(v); if (k === "id") this.id = String(v); if (k === "class") this.className = String(v); if (k === "value") this.value = String(v); }
  getAttribute(k) { return this.attrs[k]; }
  append(...n) { for (const x of n) this.children.push(typeof x === "string" ? new TextNode(x) : x); }
  replaceChildren(...n) { this.children = []; this.append(...n.filter((x) => x !== null && x !== undefined)); }
  addEventListener(t, f) { (this.listeners[t] ||= []).push(f); }
  async dispatch(t, ev = {}) { for (const f of this.listeners[t] || []) await f({ preventDefault() {}, target: this, key: ev.key, ...ev }); }
  click() { if (this.tag === "a" && this.attrs.href?.startsWith("#")) { location.hash = this.attrs.href; } return this.dispatch("click"); }
  get classList() { const self = this; return {
    add: (c) => { if (!self.className.split(" ").includes(c)) self.className = (self.className + " " + c).trim(); },
    remove: (c) => { self.className = self.className.split(" ").filter((x) => x && x !== c).join(" "); },
    contains: (c) => self.className.split(" ").includes(c) }; }
  get textContent() { return this.children.map((c) => c.textContent).join(""); }
  set textContent(v) { this.children = [new TextNode(v)]; }
  focus() {} select() {} setSelectionRange() {} remove() {}
}
const all = (n, pred, out = []) => { if (n.nodeType === 1) { if (pred(n)) out.push(n); n.children.forEach((c) => all(c, pred, out)); } return out; };

const appRoot = new El("div");
globalThis.document = {
  getElementById: (id) => (id === "app" ? appRoot : all(appRoot, (e) => e.id === id)[0] || null),
  createElement: (t) => new El(t), createTextNode: (t) => new TextNode(t),
  activeElement: null, hidden: false, body: { append() {} }, head: { append() {} }, execCommand: () => false,
};
const mem = () => { const m = new Map(); return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k) }; };
Object.defineProperty(globalThis, "localStorage", { value: mem(), configurable: true, writable: true });
Object.defineProperty(globalThis, "sessionStorage", { value: mem(), configurable: true, writable: true });
const hashHandlers = []; let _hash = "";
globalThis.location = { origin: "http://test", pathname: "/",
  get hash() { return _hash; },
  set hash(v) { const nv = v.startsWith("#") ? v : "#" + v; if (nv !== _hash) { _hash = nv; setTimeout(() => hashHandlers.forEach((f) => f()), 0); } } };
globalThis.window = { addEventListener: (t, f) => { if (t === "hashchange") hashHandlers.push(f); } };
globalThis.SECURESUM_API = BASE;
globalThis.confirm = () => true;                    // pretend the user clicks OK in confirm dialogs
let lastBlob = null;                                // capture downloads (CSV)
const realCreate = URL.createObjectURL;
URL.createObjectURL = (b) => { lastBlob = b; return realCreate(b); };

// ---------------- helpers ----------------
const text = () => appRoot.textContent;
async function waitFor(pred, label, ms = 15000) {
  const t0 = Date.now();
  while (Date.now() - t0 < ms) { try { if (pred()) return; } catch (e) { /* retry */ } await new Promise((r) => setTimeout(r, 50)); }
  throw new Error(`Timed out waiting for: ${label}\n--- page text ---\n${text().slice(0, 800)}`);
}
const byId = (id) => all(appRoot, (e) => e.id === id)[0];
const button = (label) => all(appRoot, (e) => (e.tag === "button" || e.tag === "a") && e.textContent.includes(label))[0];
const step = (m) => console.log("  ok  -", m);

const { makeApi, joinWithNewKey, sendShares, sendPartial } = await import("../frontend/js/protocol.js");
async function codeFor(email) {
  return (await (await fetch(`${BASE}/__test/code?email=${encodeURIComponent(email)}`)).json()).code;
}
const formOf = (id) => all(appRoot, (e) => e.tag === "form" && all(e, (x) => x.id === id).length)[0];
const exactBtn = (label) => all(appRoot, (e) => (e.tag === "button" || e.tag === "a") && e.textContent === label)[0];
class Client {
  constructor(name) { this.name = name; this.token = null; this.keys = new Map(); this.api = makeApi(BASE, () => this.token); }
  get ks() { return { get: async (u, s) => this.keys.get(`${u}:${s}`) || null, set: async (u, s, e) => { this.keys.set(`${u}:${s}`, e); } }; }
  async register() {
    const email = `${this.name}${Date.now()}@example.com`.toLowerCase();
    await this.api("POST", "/api/auth/register", { email, password: "password123", name: this.name });
    const r = await this.api("POST", "/api/auth/verify", { email, code: await codeFor(email) });
    this.token = r.token; this.user = r.user; return this;
  }
  join(code) { return joinWithNewKey(this.api, this.ks, this.user.id, code); }
  async send(id, v) { return sendShares(this.api, this.ks, this.user.id, await this.api("GET", `/api/sessions/${id}`), v); }
  async partial(id) { return sendPartial(this.api, this.ks, this.user.id, await this.api("GET", `/api/sessions/${id}`)); }
}

console.log("SecureSum UI smoke test against", BASE);
const app = await import("../frontend/js/app.js");

// 1. landing / auth
await waitFor(() => text().includes("Compute together"), "landing page");
step("landing page renders");
await button("Create account").click();
await waitFor(() => byId("name"), "register form");
const ashaEmail = `asha${Date.now()}@example.com`;
byId("name").value = "Asha"; byId("email").value = ashaEmail; byId("password").value = "password123";
await all(appRoot, (e) => e.tag === "form")[0].dispatch("submit");
await waitFor(() => text().includes("Check your email") && text().includes(ashaEmail), "verify screen");
assert.ok(!text().includes("Welcome, Asha"), "not logged in before verification");
byId("code").value = "000000";
await all(appRoot, (e) => e.tag === "form")[0].dispatch("submit");
await waitFor(() => text().includes("wrong or has expired"), "wrong code message");
byId("code").value = await codeFor(ashaEmail);
await all(appRoot, (e) => e.tag === "form")[0].dispatch("submit");
await waitFor(() => text().includes("Dashboard") && text().includes("Welcome, Asha"), "dashboard after verification");
step("register -> check-your-email screen -> wrong code refused -> right code -> dashboard");

// 2. new session with privacy warning
location.hash = "#/new";
await waitFor(() => text().includes("Number of parties"), "new session form");
byId("title").value = "Salary benchmark";
byId("n").value = "2"; await byId("n").dispatch("input");
const warn = all(appRoot, (e) => e.className.includes("warn"))[0];
assert.ok(!warn.className.includes("hidden") && warn.textContent.includes("reveals the other person"), "n=2 warning shown");
byId("n").value = "3"; await byId("n").dispatch("input");
assert.ok(warn.className.includes("hidden"), "n=3 warning hidden");
byId("metric").value = "sum"; byId("decimals").value = "0";   // a real browser preselects the first option
await all(appRoot, (e) => e.tag === "form")[0].dispatch("submit");
await waitFor(() => text().includes("Salary benchmark") && text().includes("Join as a party"), "session room (creator, not joined)");
step("new session (3 parties); warning appears only for n < 3");

const code = all(appRoot, (e) => e.attrs["aria-label"] === "Invite link")[0].value.split("#/join/")[1];
assert.match(code, /^[a-z0-9]{12}$/);

// 3. join through the UI
location.hash = `#/join/${code}`;
await waitFor(() => text().includes("Invited by Asha"), "join page");
await all(appRoot, (e) => e.tag === "button" && e.textContent === "Join this session")[0].click();
await waitFor(() => text().includes("Waiting for parties to join") && text().includes("You are party 1"), "joined, waiting");
step("join via invite link creates a key and shows waiting state");

// 4. other two parties join through the API
const b = await new Client("Bala").register(), c = await new Client("Chitra").register();
await b.join(code); await c.join(code);
const sid = Number(/session\/(\d+)/.exec(location.hash)[1]);
await waitFor(() => byId("value-input"), "value input after all joined", 10000);
step("page updates itself when the other parties join");

// 5. enter value in the UI
byId("value-input").value = "100"; await byId("value-input").dispatch("input");
await button("Split and send encrypted shares").click();
await waitFor(() => text().includes("Your encrypted shares are sent") && text().includes("How your number was split"), "shares sent");
step("value split and encrypted shares sent; shares table shown");

// 6. rest of the protocol
await b.send(sid, "200"); await c.send(sid, "300");
await waitFor(() => text().includes("Your partial sum is published"), "auto partial sum", 12000);
step("partial sum computed and published automatically");
await b.partial(sid); await c.partial(sid);
await waitFor(() => text().includes("Total across 3 parties") && all(appRoot, (e) => e.className.includes("big-number"))[0]?.textContent === "600", "result", 12000);
step("result 100 + 200 + 300 = 600 shown");
assert.ok(text().includes("Average: 200.00"));
assert.ok(!text().includes("\"privateJwk\""), "no key material on the page");

// 7. dashboard, finished-session options
const exact = (label) => all(appRoot, (e) => (e.tag === "button" || e.tag === "a") && e.textContent === label)[0];
await exact("Download result (CSV)").click();
const csv = await lastBlob.text();
const bytes = new Uint8Array(await lastBlob.arrayBuffer());
assert.deepEqual([...bytes.slice(0, 3)], [0xef, 0xbb, 0xbf], "UTF-8 byte-order mark for Excel");
for (const want of ['"Field","Value"', '"Session title","Salary benchmark"', '"Status","Completed"', '"Parties","3"',
  '"Total","600"', '"Average","200.00"', '"Number format","Whole numbers"', '"Downloaded by","Asha"',
  '"Created by","Asha"', '"Party #","Name"', '"Asha"', '"Bala"', '"Chitra"', '"Activity log"',
  "No individual value was revealed"]) assert.ok(csv.includes(want), `CSV is missing ${want}\n${csv}`);
for (const never of ["@example.com", "privateJwk", "public_key", '"100"']) {
  assert.ok(!csv.includes(never), `CSV must not contain ${never}`);
}
// shares and partial sums are long random numbers; nothing like that may appear (dates have at most 4 digits in a row)
assert.ok(!/\d{9,}/.test(csv), "CSV must not contain any long random number");
// the note is honest for small sessions, and spreadsheet formulas in titles are defused
const fake = (n, title) => ({ id: 9, title, n_parties: n, metric: "sum", decimals: 2, creator_name: "X", created_at: "t",
  result: { sum: "1.00", average: "1.0000" }, participants: [{ idx: 1, name: "=HACK()" }], audit: [] });
assert.ok(app.resultCsv(fake(2, "T")).includes("reveals the other person"));
assert.ok(app.resultCsv(fake(3, "T")).includes("No individual value was revealed"));
assert.ok(app.resultCsv(fake(3, "=SUM(1)")).includes("\"'=SUM(1)\"") && app.resultCsv(fake(3, "T")).includes("\"'=HACK()\""));
assert.ok(exact("Run again with same settings").attrs.href.includes("n=3"));
step("finished session: CSV has the right fields, no secrets, honest note, Excel-safe; 'Run again' link");

await exact("Remove from my list").click();
await waitFor(() => text().includes("Welcome, Asha") && text().includes("Nothing in progress"), "dashboard after archive");
await exact("Archived").click();
await waitFor(() => text().includes("Salary benchmark") && text().includes("Restore to dashboard"), "archived tab");
await exact("Restore to dashboard").click();
await waitFor(() => text().includes("Nothing archived"), "restored");
await exact("Completed").click();
await waitFor(() => text().includes("Salary benchmark") && text().includes("Result ready"), "completed tab");
step("remove from list -> Archived tab -> restore -> Completed tab");

await exact("Delete").click();
await waitFor(() => text().includes("No finished sessions yet"), "deleted");
await assert.rejects(() => b.api("GET", `/api/sessions/${sid}`), /not found/i);
step("creator deletes the session from the dashboard; other parties lose access");

// "Run again" prefills the new-session form
location.hash = "#/new?title=Salary%20benchmark&n=5&metric=average&decimals=2";
await waitFor(() => byId("title") && byId("title").value === "Salary benchmark", "prefilled form");
assert.equal(byId("n").value, 5); assert.equal(byId("metric").value, "average"); assert.equal(byId("decimals").value, 2);
step("new-session form is prefilled by 'Run again'");

// account settings
location.hash = "#/account";
await waitFor(() => byId("profile-name") && text().includes("This device"), "account page");
assert.ok(text().includes(ashaEmail) && text().includes("Verified") && text().includes("Chrome on macOS") === false);
byId("profile-name").value = "Asha K";
await formOf("profile-name").dispatch("submit");
await waitFor(() => text().includes("Name saved.") && text().includes("Asha K"), "name saved");
step("account page: profile, verified badge, devices, rename");
byId("old-password").value = "password123"; byId("new-password").value = "newpass12345"; byId("new-password2").value = "different";
await formOf("old-password").dispatch("submit");
await waitFor(() => text().includes("do not match"), "mismatch message");
byId("old-password").value = "wrong-old-password"; byId("new-password2").value = "newpass12345";
await formOf("old-password").dispatch("submit");
await waitFor(() => text().includes("current password is wrong"), "wrong current password");
assert.ok(text().includes("Account settings"), "a wrong password must NOT log you out");
byId("old-password").value = "password123";
await formOf("old-password").dispatch("submit");
await waitFor(() => text().includes("Password changed"), "password changed");
step("account page: password change (mismatch and wrong password handled, no logout)");

// forgot password through the UI
await exactBtn("Log out").click();
await waitFor(() => text().includes("Compute together"), "after logout");
location.hash = "#/forgot";
await waitFor(() => byId("email") && text().includes("we will send a 6-digit code to reset the password"), "forgot page");
byId("email").value = ashaEmail;
await formOf("email").dispatch("submit");
await waitFor(() => text().includes("Enter the code"), "code step");
byId("code").value = await codeFor(ashaEmail);
byId("new-password").value = "resetpass123"; byId("new-password2").value = "resetpass123";
await formOf("code").dispatch("submit");
await waitFor(() => text().includes("Password changed. Log in with your new password."), "login page with notice");
byId("email").value = ashaEmail; byId("password").value = "resetpass123";
await formOf("email").dispatch("submit");
await waitFor(() => text().includes("Welcome, Asha K"), "login with the reset password");
step("forgot password: code -> new password -> log in with it");

// delete account (nothing unfinished is left)
location.hash = "#/account";
await waitFor(() => byId("delete-password"), "delete form");
byId("delete-password").value = "wrong-password";
await formOf("delete-password").dispatch("submit");
await waitFor(() => text().includes("password is wrong"), "wrong password on delete");
byId("delete-password").value = "resetpass123";
await formOf("delete-password").dispatch("submit");
await waitFor(() => text().includes("Your account was deleted."), "account deleted");
await assert.rejects(() => new Client("x").api("POST", "/api/auth/login", { email: ashaEmail, password: "resetpass123" }), /Wrong email/);
step("delete account: wrong password refused, then account closed and login impossible");

// Google sign-in button is shown when the server has a client id; the credential handler logs in
await waitFor(() => byId("google-btn"), "Google button container");
await app.handleGoogleCredential("fake:g1:gina@example.com:Gina:true", null);
await waitFor(() => text().includes("Welcome, Gina"), "logged in with Google");
location.hash = "#/account";
await waitFor(() => text().includes("Add a password") && text().includes("comes from your Google account"), "google account page");
assert.ok(text().includes("Add a password above first"), "delete needs a password first");
step("Google: button container present, credential logs in, account page explains password/email rules");

// 8. logout
await exactBtn("Log out").click();
await waitFor(() => text().includes("Compute together"), "after logout");
step("log out returns to the landing page");

console.log("\nUI smoke test passed.");
process.exit(0);
