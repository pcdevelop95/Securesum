// SecureSum web app. All text goes through textContent (never innerHTML), so user input cannot inject markup.
//All screens: Login, Dashboard, Session Page, and Account Settings.
import { fingerprint, requireCrypto } from "./crypto.js";
import {
  joinWithNewKey, makeApi, makeBackup, parseBackup, sendPartial, sendShares,
} from "./protocol.js";

const BASE = globalThis.SECURESUM_API || "";
const root = document.getElementById("app");

// ------------------------------------------------------------------ small helpers
function store(kind) {
  const area = () => (kind === "session" ? globalThis.sessionStorage : globalThis.localStorage);
  return {
    get(k) { try { return area().getItem(k); } catch (e) { return null; } },
    set(k, v) { try { area().setItem(k, v); return true; } catch (e) { return false; } },
    del(k) { try { area().removeItem(k); } catch (e) { /* ignore */ } },
  };
}
const ls = store("local");
const ss = store("session");

function h(tag, props, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2).toLowerCase(), v);
    else if (k === "value") el.value = v;
    else el.setAttribute(k, v === true ? "" : String(v));
  }
  for (const kid of kids.flat(Infinity)) {
    if (kid === null || kid === undefined || kid === false) continue;
    el.append(typeof kid === "object" ? kid : document.createTextNode(String(kid)));
  }
  return el;
}

function initials(name) {
  const parts = String(name || "?").trim().split(/\s+/).filter(Boolean);
  return ((parts[0] || "?")[0] + (parts.length > 1 ? parts[parts.length - 1][0] : "")).toUpperCase();
}

function describeAgent(ua) {
  ua = ua || "";
  const browser = /Edg\//.test(ua) ? "Edge" : /OPR\/|Opera/.test(ua) ? "Opera" : /Chrome\//.test(ua) ? "Chrome"
    : /Firefox\//.test(ua) ? "Firefox" : /Safari\//.test(ua) ? "Safari" : "Browser";
  const os = /iPhone|iPad/.test(ua) ? "iOS" : /Android/.test(ua) ? "Android" : /Mac OS X|Macintosh/.test(ua) ? "macOS"
    : /Windows/.test(ua) ? "Windows" : /Linux/.test(ua) ? "Linux" : "an unknown device";
  return `${browser} on ${os}`;
}

const plural = (n, one, many) => (n === 1 ? one : many);
const partyWord = (n) => `${n} ${plural(n, "party", "parties")}`;
function fmtTime(iso) {
  const d = new Date(iso);
  return isNaN(d) ? iso : d.toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
}
function showError(el, msg) { el.textContent = msg; el.classList.remove("hidden"); }
function alertBox(kind, ...kids) { return h("div", { class: `alert ${kind}`, role: kind === "error" ? "alert" : "status" }, ...kids); }

function formatScaled(text, decimals) {
  if (!decimals) return text;
  const padded = text.padStart(decimals + 1, "0");
  return `${padded.slice(0, -decimals)}.${padded.slice(-decimals)}`;
}

function privacyNote(n) {
  if (n >= 3) return null;
  if (n === 1) {
    return "With 1 party there is nobody to hide your number from. This is only useful for trying the app.";
  }
  return "With 2 parties the result itself reveals the other person's number (you know your own number, so you can subtract it). " +
    "This is a limit of the maths, not a bug. Use 3 or more parties for real privacy.";
}

async function copyText(text, inputEl) {
  try {
    if (globalThis.navigator && navigator.clipboard) { await navigator.clipboard.writeText(text); return true; }
  } catch (e) { /* fall through */ }
  try { inputEl.select(); return document.execCommand("copy"); } catch (e) { return false; }
}

function downloadFile(name, text, type) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = h("a", { href: url, download: name });
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1500);
}

// Spreadsheet programs run text that starts with = + - @ as a formula, so we defuse it.
function csvCell(v) {
  let t = String(v ?? "");
  if (/^[=+\-@\t\r]/.test(t)) t = "'" + t;
  return `"${t.replace(/"/g, '""')}"`;
}

function resultCsv(s) {
  const done = s.audit.find((e) => e.event === "result_ready");
  const format = s.decimals ? `Up to ${s.decimals} decimal place${s.decimals === 1 ? "" : "s"}` : "Whole numbers";
  const note = privacyNote(s.n_parties) ||
    "Computed with SecureSum. No individual value was revealed to the server or to the other parties.";
  // Deliberately NOT included: anyone's value, shares, partial sums, keys or e-mail addresses.
  const rows = [
    ["Field", "Value"],
    ["Session ID", s.id], ["Session title", s.title], ["Status", "Completed"], ["Created by", s.creator_name],
    ["Parties", s.n_parties], ["Revealed", s.metric === "sum" ? "Total" : "Average"],
    ["Total", s.result.sum], ["Average", s.result.average], ["Number format", format],
    ["Created at (UTC)", s.created_at], ["Completed at (UTC)", done ? done.at : ""],
    ["Downloaded by", user ? user.name : ""], ["Downloaded at (UTC)", new Date().toISOString()],
    ["Privacy note", note],
    [],
    ["Parties"], ["Party #", "Name"], ...s.participants.map((p) => [p.idx, p.name]),
    [],
    ["Activity log"], ["Time (UTC)", "Event"], ...s.audit.map((e) => [e.at, auditText(e)]),
  ];
  // The byte-order mark makes Excel on Mac/Windows read names in any language correctly.
  return "\uFEFF" + rows.map((r) => r.map(csvCell).join(",")).join("\r\n") + "\r\n";
}

// ------------------------------------------------------------------ auth + api state
let token = ls.get("ss_token");
let user = null;
const rawApi = makeApi(BASE, () => token);

function clearAuth() { token = null; user = null; ls.del("ss_token"); }

async function api(method, path, body) {
  try {
    return await rawApi(method, path, body);
  } catch (e) {
    if (e.status === 401 && e.code === "session_expired" && token) {
      clearAuth();
      if (location.hash !== "#/login") location.hash = "#/login";
    }
    throw e;
  }
}

const keyStore = {
  async get(uid, sid) {
    const t = ls.get(`ss_key_${uid}_${sid}`);
    if (!t) return null;
    try { return JSON.parse(t); } catch (e) { return null; }
  },
  async set(uid, sid, entry) {
    if (!ls.set(`ss_key_${uid}_${sid}`, JSON.stringify(entry))) {
      throw new Error("This browser blocked storage, so your secret key could not be saved.");
    }
  },
};

function storageWorks() {
  const ok = ls.set("ss_probe", "1");
  ls.del("ss_probe");
  return ok;
}

// ------------------------------------------------------------------ layout + routing
const cleanups = [];
let routeSeq = 0;

function go(hash) {
  if (location.hash === hash) route();
  else location.hash = hash;
}

async function doLogout() {
  try { await rawApi("POST", "/api/auth/logout"); } catch (e) { /* ignore */ }
  clearAuth();
  go("#/login");
}

function shell(content) {
  const bar = h("header", { class: "topbar" },
    h("a", { class: "brand", href: "#/" }, h("span", { class: "brand-mark", "aria-hidden": "true" }, "\u03A3"), "SecureSum"),
    user ? h("nav", {}, h("a", { class: "navlink", href: "#/" }, "Dashboard"),
      h("a", { class: "navlink", href: "#/account" }, h("span", { class: "avatar", "aria-hidden": "true" }, initials(user.name)), "Account"),
      h("span", { class: "who" }, user.name),
      h("button", { class: "btn ghost", type: "button", onClick: doLogout }, "Log out")) : null);
  const main = h("main", { class: "container" }, content);
  const foot = h("p", { class: "footer" },
    "Your numbers are split and encrypted in your browser. The server only sees encrypted pieces.");
  root.replaceChildren(bar, main, foot);
}

function errorCard(message) {
  return h("div", { class: "card" }, h("h1", {}, "Something went wrong"),
    alertBox("error", message), h("a", { class: "btn", href: "#/" }, "Back to your sessions"));
}

async function route() {
  const rid = ++routeSeq;
  const isCurrent = () => rid === routeSeq;
  while (cleanups.length) { try { cleanups.pop()(); } catch (e) { /* ignore */ } }
  const raw = (location.hash || "").replace(/^#\/?/, "");
  const [pathPart, queryPart = ""] = raw.split("?");
  const parts = pathPart.split("/").filter(Boolean);
  const [page, arg] = parts;
  const params = new URLSearchParams(queryPart);

  if (!token) {
    if (page === "join" && arg) ss.set("ss_next", `#/join/${arg}`);
    await loadConfig();
    if (!isCurrent()) return;
    if (page === "verify") verifyView(params.get("email"));
    else if (page === "forgot") forgotView();
    else authView(page === "register" ? "register" : "login");
    return;
  }
  if (!user) {
    try { user = (await api("GET", "/api/me")).user; }
    catch (e) { if (isCurrent()) authView("login"); return; }
    if (!isCurrent()) return;
  }
  try {
    if (page === "new") newSessionView(params);
    else if (page === "account") await accountView(isCurrent);
    else if (page === "join" && arg) await joinView(arg.toLowerCase(), isCurrent);
    else if (page === "session" && /^\d+$/.test(arg || "")) await sessionView(Number(arg), isCurrent);
    else await dashboardView(isCurrent);
  } catch (e) {
    if (isCurrent()) shell(errorCard(e.message));
  }
}

// ------------------------------------------------------------------ login / register / verify / reset
let appConfig = null;
async function loadConfig() {
  if (appConfig) return appConfig;
  try { appConfig = await rawApi("GET", "/api/config"); }
  catch (e) { appConfig = { google_client_id: null, email_delivery: "smtp" }; }
  return appConfig;
}

let flash = "";   // one-time message shown on the login page (e.g. "Password changed")

function finishLogin(r) {
  token = r.token; user = r.user; ls.set("ss_token", token);
  const next = ss.get("ss_next"); ss.del("ss_next");
  go(next && next.startsWith("#/join/") ? next : "#/");
}

function field(label, type, id, autocomplete, extra) {
  const input = h("input", { type, id, name: id, autocomplete, required: true, ...(extra || {}) });
  return { input, wrap: h("div", { class: "field" }, h("label", { for: id }, label), input) };
}

function consoleHint() {
  return appConfig && appConfig.email_delivery === "console"
    ? alertBox("warn", "This server is not connected to an email service yet, so the code was printed in the server's terminal window (where you ran python run.py).")
    : null;
}

// ---- Google sign-in (Google Identity Services). Only active when the server has a GOOGLE_CLIENT_ID.
function loadGoogleScript() {
  return new Promise((resolve, reject) => {
    if (globalThis.google && google.accounts && google.accounts.id) { resolve(); return; }
    const sc = h("script", { src: "https://accounts.google.com/gsi/client", async: true, defer: true });
    sc.addEventListener("load", () => resolve());
    sc.addEventListener("error", () => reject(new Error("blocked")));
    document.head.append(sc);
  });
}

async function handleGoogleCredential(credential, errBox) {
  try {
    finishLogin(await rawApi("POST", "/api/auth/google", { credential }));
  } catch (e) {
    if (errBox) showError(errBox, e.message); else throw e;
  }
}

async function startGoogleButton(box, errBox) {
  try {
    await loadGoogleScript();
    google.accounts.id.initialize({
      client_id: appConfig.google_client_id,
      callback: (resp) => handleGoogleCredential(resp.credential, errBox),
    });
    google.accounts.id.renderButton(box, { theme: "outline", size: "large", text: "continue_with", shape: "rectangular", width: 320 });
  } catch (e) {
    box.textContent = "Google sign-in could not be loaded. It may be blocked by your browser or network.";
  }
}

function authView(mode) {
  let current = mode;
  const notice = flash; flash = "";
  const card = h("div", { class: "card" });
  const googleOn = !!(appConfig && appConfig.google_client_id);
  const googleBox = h("div", { class: "google-box", id: "google-btn" });
  const googleErr = h("div", { class: "alert error hidden", role: "alert" });

  function drawForm() {
    const register = current === "register";
    const err = h("div", { class: "alert error hidden", role: "alert" });
    const name = register ? field("Your name or company", "text", "name", "name", { maxlength: 60 }) : null;
    const email = field("Email", "email", "email", "email", { maxlength: 120 });
    const pw = field("Password", "password", "password", register ? "new-password" : "current-password", { minlength: 8, maxlength: 200 });
    const btn = h("button", { class: "btn", type: "submit" }, register ? "Create account" : "Log in");
    const toVerify = (addr) => go(`#/verify?email=${encodeURIComponent(addr)}`);
    const form = h("form", {
      onSubmit: async (ev) => {
        ev.preventDefault();
        btn.disabled = true; err.classList.add("hidden");
        try {
          const body = { email: email.input.value, password: pw.input.value };
          if (register) body.name = name.input.value;
          const r = await rawApi("POST", register ? "/api/auth/register" : "/api/auth/login", body);
          if (register) toVerify(r.email); else finishLogin(r);
        } catch (e) {
          if (e.code === "email_not_verified") toVerify(email.input.value.trim().toLowerCase());
          else showError(err, e.message);
        } finally { btn.disabled = false; }
      },
    }, err, name && name.wrap, email.wrap, pw.wrap, h("div", { class: "row" }, btn),
    register ? h("p", { class: "hint" }, "We will email you a 6-digit code to confirm that this address is yours. Use at least 8 characters for the password.")
      : h("p", { class: "hint" }, h("a", { href: "#/forgot" }, "Forgot password?")));
    const tab = (id, label) => h("button", { type: "button", class: "tab" + (current === id ? " active" : ""),
      onClick: () => { current = id; drawForm(); } }, label);
    card.replaceChildren(
      notice ? alertBox("ok", notice) : null,
      h("div", { class: "tabs" }, tab("login", "Log in"), tab("register", "Create account")), form,
      googleOn ? h("div", { class: "divider" }, h("span", {}, "or")) : null, googleOn ? googleBox : null, googleOn ? googleErr : null);
  }
  drawForm();

  shell(h("div", { class: "hero" },
    h("div", {},
      h("h1", {}, "Compute together. Reveal nothing."),
      h("p", { class: "lead" }, "Companies calculate a total or an average together, while every individual number stays private."),
      h("ul", { class: "points" },
        h("li", {}, "Choose any number of parties. Each one enters a private number."),
        h("li", {}, "Numbers are split into random pieces and encrypted in your browser."),
        h("li", {}, "The server never sees a real value, only encrypted pieces."),
        h("li", {}, "Everyone gets the same final result, and nothing else."))),
    card));
  if (googleOn) startGoogleButton(googleBox, googleErr);
}

function verifyView(email) {
  email = (email || "").trim().toLowerCase();
  if (!email) { go("#/login"); return; }
  const err = h("div", { class: "alert error hidden", role: "alert" });
  const info = h("div", { class: "alert ok hidden", role: "status" });
  const code = h("input", { type: "text", id: "code", name: "code", inputmode: "numeric", autocomplete: "one-time-code",
    maxlength: 6, pattern: "[0-9]{6}", required: true, placeholder: "123456" });
  const btn = h("button", { class: "btn", type: "submit" }, "Verify and continue");
  const resend = h("button", { class: "btn light small", type: "button" }, "Resend code");
  let wait = 60;
  const tick = () => { resend.disabled = wait > 0; resend.textContent = wait > 0 ? `Resend code (${wait}s)` : "Resend code"; };
  tick();
  const timer = setInterval(() => { if (wait > 0) { wait--; tick(); } }, 1000);
  cleanups.push(() => clearInterval(timer));
  resend.addEventListener("click", async () => {
    err.classList.add("hidden");
    try { await rawApi("POST", "/api/auth/resend", { email }); showError(info, "If this address is waiting for verification, a new code is on its way."); wait = 60; tick(); }
    catch (e) { showError(err, e.message); }
  });
  const form = h("form", {
    onSubmit: async (ev) => {
      ev.preventDefault();
      btn.disabled = true; err.classList.add("hidden");
      try { finishLogin(await rawApi("POST", "/api/auth/verify", { email, code: code.value.trim() })); }
      catch (e) { showError(err, e.message); }
      finally { btn.disabled = false; }
    },
  }, h("div", { class: "field" }, h("label", { for: "code" }, "6-digit code"), code), h("div", { class: "row" }, btn));
  shell(h("div", { class: "auth-narrow" }, h("div", { class: "card" },
    h("h1", {}, "Check your email"),
    h("p", {}, "We sent a 6-digit code to ", h("strong", {}, email), ". It expires in 15 minutes."),
    consoleHint(), err, info, form,
    h("div", { class: "row between" }, resend, h("a", { href: "#/register", class: "small" }, "Use a different email")))));
}

function forgotView() {
  const card = h("div", { class: "card" });
  let email = "";

  function stepEmail() {
    const err = h("div", { class: "alert error hidden", role: "alert" });
    const f = field("Email", "email", "email", "email", { maxlength: 120 });
    const btn = h("button", { class: "btn", type: "submit" }, "Send me a code");
    card.replaceChildren(h("h1", {}, "Forgot password"),
      h("p", { class: "muted" }, "Enter your email. If an account exists, we will send a 6-digit code to reset the password."),
      h("form", { onSubmit: async (ev) => {
        ev.preventDefault(); btn.disabled = true; err.classList.add("hidden");
        try { await rawApi("POST", "/api/auth/forgot", { email: f.input.value }); email = f.input.value.trim().toLowerCase(); stepCode(); }
        catch (e) { showError(err, e.message); } finally { btn.disabled = false; }
      } }, err, f.wrap, h("div", { class: "row" }, btn, h("a", { class: "btn light", href: "#/login" }, "Back to login"))));
  }

  function stepCode() {
    const err = h("div", { class: "alert error hidden", role: "alert" });
    const code = field("6-digit code", "text", "code", "one-time-code", { inputmode: "numeric", maxlength: 6, pattern: "[0-9]{6}" });
    const pw = field("New password (at least 8 characters)", "password", "new-password", "new-password", { minlength: 8, maxlength: 200 });
    const pw2 = field("Repeat new password", "password", "new-password2", "new-password");
    const btn = h("button", { class: "btn", type: "submit" }, "Set new password");
    card.replaceChildren(h("h1", {}, "Enter the code"),
      h("p", { class: "muted" }, "If ", h("strong", {}, email), " has an account, a code was sent to it."), consoleHint(),
      h("form", { onSubmit: async (ev) => {
        ev.preventDefault(); err.classList.add("hidden");
        if (pw.input.value !== pw2.input.value) { showError(err, "The two passwords do not match."); return; }
        btn.disabled = true;
        try {
          await rawApi("POST", "/api/auth/reset", { email, code: code.input.value.trim(), new_password: pw.input.value });
          flash = "Password changed. Log in with your new password."; go("#/login");
        } catch (e) { showError(err, e.message); } finally { btn.disabled = false; }
      } }, err, code.wrap, pw.wrap, pw2.wrap, h("div", { class: "row" }, btn,
        h("button", { class: "btn light", type: "button", onClick: stepEmail }, "Use a different email"))));
  }

  shell(h("div", { class: "auth-narrow" }, card));
  stepEmail();
}

// ------------------------------------------------------------------ dashboard
const STATE_LABEL = {
  waiting: "Waiting for parties", sharing: "Collecting shares", summing: "Adding up", done: "Result ready",
};
const stateBadge = (state) => h("span", { class: `badge b-${state}` }, STATE_LABEL[state] || state);

let dashTab = "active";

async function dashboardView(isCurrent) {
  const main = await api("GET", "/api/sessions");
  const archived = dashTab === "archived" ? await api("GET", "/api/sessions?archived=1") : null;
  if (!isCurrent()) return;
  const all = main.sessions;
  const inProgress = all.filter((s) => s.state !== "done");
  const completed = all.filter((s) => s.state === "done");
  const list = dashTab === "archived" ? archived.sessions : dashTab === "completed" ? completed : inProgress;

  const joinInput = h("input", { type: "text", id: "join-code", placeholder: "Paste invite link or code", "aria-label": "Invite link or code" });
  const joinNow = () => {
    const text = joinInput.value.trim();
    const m = text.match(/join\/([A-Za-z0-9]+)/);
    const code = (m ? m[1] : text).toLowerCase();
    if (/^[a-z0-9]{6,20}$/.test(code)) go(`#/join/${code}`);
    else joinInput.focus();
  };
  const errBox = h("div", { class: "alert error hidden", role: "alert" });
  const act = (fn) => async () => {
    try { await fn(); route(); } catch (e) { showError(errBox, e.message); }
  };

  const cards = list.map((s) => {
    const buttons = [h("a", { class: "btn small", href: `#/session/${s.id}` }, "Open")];
    if (dashTab === "archived") {
      buttons.push(h("button", { class: "btn light small", type: "button",
        onClick: act(() => api("POST", `/api/sessions/${s.id}/unhide`)) }, "Restore to dashboard"));
    } else if (s.state === "done") {
      buttons.push(h("button", { class: "btn light small", type: "button",
        onClick: act(() => api("POST", `/api/sessions/${s.id}/hide`)) }, "Remove from my list"));
    }
    if (s.is_creator) {
      buttons.push(h("button", { class: "btn danger small", type: "button", onClick: act(async () => {
        const warn = s.state === "done" ? "The result will be lost for all parties." : "This cancels it for all parties.";
        if (!confirm(`Delete "${s.title}" for everyone? ${warn} This cannot be undone.`)) throw new Error("Not deleted.");
        await api("DELETE", `/api/sessions/${s.id}`);
      }) }, "Delete"));
    }
    return h("div", { class: "card" },
      h("div", { class: "row between" }, h("h3", {}, h("a", { href: `#/session/${s.id}` }, s.title)), stateBadge(s.state)),
      h("p", { class: "muted small" },
        `${s.metric === "sum" ? "Total" : "Average"} \u00B7 ${s.joined} of ${partyWord(s.n_parties)} joined \u00B7 ` +
        `${s.my_idx ? `you are party ${s.my_idx}` : "you have not joined yet"} \u00B7 created by ${s.creator_name} \u00B7 ${fmtTime(s.created_at)}`),
      h("div", { class: "row" }, buttons));
  });

  const stat = (n, label) => h("div", { class: "card stat" }, h("div", { class: "stat-n" }, String(n)), h("div", { class: "muted small" }, label));
  const tab = (id, label) => h("button", { type: "button", class: "tab" + (dashTab === id ? " active" : ""),
    onClick: () => { dashTab = id; route(); } }, label);
  const empty = {
    active: ["Nothing in progress", "Create a session, choose how many parties take part, and send them the invite link. Each party enters a private number; only the total or average is revealed."],
    completed: ["No finished sessions yet", "When a session finishes, its result stays here."],
    archived: ["Nothing archived", "Finished sessions you remove from your list are kept here, and you can restore them."],
  }[dashTab];

  shell(h("div", {},
    h("div", { class: "row between" }, h("div", {}, h("h1", {}, "Dashboard"), h("p", { class: "muted" }, `Welcome, ${user.name}`)),
      h("a", { class: "btn", href: "#/new" }, "New session")),
    h("div", { class: "stats" }, stat(all.length, "Sessions"), stat(inProgress.length, "In progress"), stat(completed.length, "Completed")),
    h("div", { class: "card" }, h("h3", {}, "Got an invite?"),
      h("div", { class: "invite" }, joinInput, h("button", { class: "btn light", type: "button", onClick: joinNow }, "Join"))),
    h("div", { class: "tabs" }, tab("active", "In progress"), tab("completed", "Completed"), tab("archived", "Archived")),
    errBox,
    cards.length ? h("div", { class: "list" }, cards) : h("div", { class: "card" }, h("h3", {}, empty[0]), h("p", { class: "muted" }, empty[1]))));
}

// ------------------------------------------------------------------ new session
function newSessionView(params) {
  params = params || new URLSearchParams();
  const err = h("div", { class: "alert error hidden", role: "alert" });
  const title = h("input", { type: "text", id: "title", maxlength: 80, required: true, placeholder: "e.g. Engineering salary benchmark" });
  const nInput = h("input", { type: "number", id: "n", min: 1, max: 50, value: 3, required: true });
  const note = h("div", { class: "alert warn hidden" });
  const metric = h("select", { id: "metric" }, h("option", { value: "sum" }, "Total (sum of all numbers)"),
    h("option", { value: "average" }, "Average"));
  const decimals = h("select", { id: "decimals" },
    [0, 1, 2, 3, 4].map((d) => h("option", { value: d }, d === 0 ? "Whole numbers only" : `Up to ${d} decimal place${d === 1 ? "" : "s"}`)));
  const btn = h("button", { class: "btn", type: "submit" }, "Create session");
  const updateNote = () => {
    const n = parseInt(nInput.value, 10);
    const t = Number.isInteger(n) ? privacyNote(n) : null;
    if (t) { note.textContent = t; note.classList.remove("hidden"); } else note.classList.add("hidden");
  };
  // "Run again" opens this page with the old settings filled in.
  const pn = parseInt(params.get("n"), 10);
  if (Number.isInteger(pn) && pn >= 1 && pn <= 50) nInput.value = pn;
  if (params.get("title")) title.value = params.get("title").slice(0, 80);
  if (["sum", "average"].includes(params.get("metric"))) metric.value = params.get("metric");
  const pd = parseInt(params.get("decimals"), 10);
  if (Number.isInteger(pd) && pd >= 0 && pd <= 4) decimals.value = pd;
  nInput.addEventListener("input", updateNote);
  updateNote();
  const form = h("form", {
    onSubmit: async (ev) => {
      ev.preventDefault();
      btn.disabled = true; err.classList.add("hidden");
      try {
        const n = parseInt(nInput.value, 10);
        if (!Number.isInteger(n) || n < 1 || n > 50) throw new Error("Number of parties must be between 1 and 50.");
        const s = await api("POST", "/api/sessions", {
          title: title.value, n_parties: n, metric: metric.value, decimals: parseInt(decimals.value, 10),
        });
        go(`#/session/${s.id}`);
      } catch (e) { showError(err, e.message); }
      finally { btn.disabled = false; }
    },
  }, err,
  h("div", { class: "field" }, h("label", { for: "title" }, "Session title"), title),
  h("div", { class: "field" }, h("label", { for: "n" }, "Number of parties (companies or people), including you"), nInput,
    h("p", { class: "hint" }, "Any number from 1 to 50. All parties must join before numbers are sent."), note),
  h("div", { class: "field" }, h("label", { for: "metric" }, "What should be revealed?"), metric),
  h("div", { class: "field" }, h("label", { for: "decimals" }, "Number format"), decimals),
  h("div", { class: "row" }, btn, h("a", { class: "btn light", href: "#/" }, "Cancel")));
  shell(h("div", {}, h("h1", {}, "New session"), h("div", { class: "card" }, form)));
}

// ------------------------------------------------------------------ join
async function joinView(code, isCurrent) {
  let pv;
  try { pv = await api("GET", `/api/invite/${encodeURIComponent(code)}`); }
  catch (e) { if (isCurrent()) shell(errorCard(e.message)); return; }
  if (!isCurrent()) return;
  if (pv.my_idx) { go(`#/session/${pv.session_id}`); return; }

  const full = pv.joined >= pv.n_parties;
  const err = h("div", { class: "alert error hidden", role: "alert" });
  const btn = h("button", { class: "btn", type: "button", disabled: full }, full ? "Session is full" : "Join this session");
  btn.addEventListener("click", async () => {
    err.classList.add("hidden"); btn.disabled = true; btn.textContent = "Creating your secret key...";
    try {
      requireCrypto();
      if (!storageWorks()) throw new Error("This browser blocks storage (private mode?). Your secret key must be saved, so please use a normal window.");
      const s = await joinWithNewKey(api, keyStore, user.id, code);
      go(`#/session/${s.id}`);
    } catch (e) { showError(err, e.message); btn.disabled = false; btn.textContent = "Join this session"; }
  });
  const note = privacyNote(pv.n_parties);
  shell(h("div", { class: "card" },
    h("h1", {}, pv.title),
    h("p", { class: "muted" }, `Invited by ${pv.creator_name} \u00B7 ${partyWord(pv.n_parties)} \u00B7 reveals the ${pv.metric === "sum" ? "total" : "average"} \u00B7 ${pv.joined} of ${pv.n_parties} joined`),
    note ? alertBox("warn", note) : null,
    alertBox("info", "When you join, a secret key is created inside this browser and saved here. " +
      "Use the same browser and device to continue, and download a backup of the key from the session page."),
    err, h("div", { class: "row" }, btn, h("a", { class: "btn light", href: "#/" }, "Back"))));
}

// ------------------------------------------------------------------ session room
function auditText(e) {
  switch (e.event) {
    case "session_created": return `${e.name} created the session`;
    case "joined": return `${e.name} joined as party ${e.detail}`;
    case "left": return `${e.name} left the session (was party ${e.detail})`;
    case "all_joined": return "All parties have joined";
    case "shares_submitted": return `${e.name} sent encrypted shares`;
    case "all_shares_in": return "All encrypted shares are in";
    case "partial_submitted": return `${e.name} published a partial sum`;
    case "result_ready": return "The result was computed";
    default: return e.event;
  }
}

function activeStep(s) {
  if (s.state === "waiting") return 1;
  if (s.state === "sharing") return 2;
  if (s.state === "summing") return s.me && s.me.partial_sent ? 4 : 3;
  return 6;
}

async function sessionView(id, isCurrent) {
  const view = h("div", {}, h("p", { class: "muted" }, "Loading..."));
  shell(view);
  const ctx = {
    s: null, sig: "", shares: null, value: "", sending: false, formError: "", partialBusy: false,
    partialError: "", importError: "", manageError: "", key: null, keyStatus: "none", fps: new Map(),
  };
  let refreshing = false;
  let timer = null;

  const signature = (s) => JSON.stringify([s.state, s.joined, s.participants.map((p) => [p.idx, p.shares_sent, p.partial_sent]),
    s.result, s.audit.length, s.me]);

  async function loadFingerprints(s) {
    for (const p of s.participants) {
      if (ctx.fps.has(p.public_key)) continue;
      try { ctx.fps.set(p.public_key, await fingerprint(p.public_key)); }
      catch (e) { ctx.fps.set(p.public_key, "unavailable"); }
    }
  }

  function keyStatusOf(s, key) {
    if (!s.me) return "none";
    if (!key) return "missing";
    const listed = s.participants.find((p) => p.idx === s.me.idx);
    return listed && listed.public_key === key.publicKeyB64 ? "ok" : "mismatch";
  }

  async function refresh(force) {
    if (refreshing && !force) return;
    refreshing = true;
    try {
      const s = await api("GET", `/api/sessions/${id}`);
      if (!isCurrent()) return;
      const sig = signature(s);
      if (force || !ctx.s || sig !== ctx.sig) {
        ctx.s = s; ctx.sig = sig;
        ctx.key = s.me ? await keyStore.get(user.id, s.id) : null;
        await loadFingerprints(s);
        ctx.keyStatus = keyStatusOf(s, ctx.key);
        draw();
      }
    } catch (e) {
      if (!isCurrent()) return;
      if (!ctx.s) shell(errorCard(e.message));
      else if (e.status === 404) {
        clearInterval(timer);
        shell(h("div", { class: "card" }, h("h1", {}, "This session no longer exists"),
          alertBox("info", "It was deleted by its creator, or you are no longer a party in it."),
          h("a", { class: "btn", href: "#/" }, "Back to dashboard")));
      }
    } finally { refreshing = false; }
    if (isCurrent()) maybeAutoPartial();
  }

  // Steps 3 + 4 run automatically in your browser once everyone has sent their shares.
  function maybeAutoPartial() {
    const s = ctx.s;
    if (!s || !s.me || s.state !== "summing" || !s.me.shares_sent || s.me.partial_sent) return;
    if (ctx.keyStatus !== "ok" || ctx.partialBusy || ctx.partialError) return;
    runPartial();
  }

  async function runPartial() {
    ctx.partialBusy = true; ctx.partialError = ""; draw();
    try {
      await sendPartial(api, keyStore, user.id, ctx.s);
    } catch (e) {
      ctx.partialError = e.message === "KEY_MISSING"
        ? "Your secret key is missing in this browser. Import your key backup below." : e.message;
    } finally { ctx.partialBusy = false; }
    await refresh(true);
  }

  async function onSend() {
    if (ctx.sending) return;
    ctx.sending = true; ctx.formError = ""; draw();
    try {
      const r = await sendShares(api, keyStore, user.id, ctx.s, ctx.value);
      ctx.shares = { shares: r.shares, value: r.value };
      ctx.value = "";
    } catch (e) { ctx.formError = e.message; }
    finally { ctx.sending = false; }
    await refresh(true);
  }

  function downloadBackup() {
    downloadFile(`securesum-key-session-${ctx.s.id}.json`, makeBackup(user.id, ctx.s.id, ctx.key), "application/json");
  }

  // ---- sections
  function headerCard(s) {
    const link = `${location.origin}${location.pathname}#/join/${s.code}`;
    const input = h("input", { type: "text", readonly: true, value: link, "aria-label": "Invite link" });
    input.addEventListener("focus", () => input.select());
    const copy = h("button", { type: "button", class: "btn light" }, "Copy link");
    copy.addEventListener("click", async () => {
      copy.textContent = (await copyText(link, input)) ? "Copied" : "Press Ctrl+C";
      setTimeout(() => { copy.textContent = "Copy link"; }, 2000);
    });
    return h("div", { class: "card" },
      h("p", { class: "small" }, h("a", { href: "#/" }, "\u2190 All sessions")),
      h("div", { class: "row between" }, h("h1", {}, s.title), stateBadge(s.state)),
      h("p", { class: "muted" }, `${partyWord(s.n_parties)} \u00B7 reveals the ${s.metric === "sum" ? "total" : "average"}` +
        `${s.decimals ? ` \u00B7 up to ${s.decimals} decimal place${s.decimals === 1 ? "" : "s"}` : " \u00B7 whole numbers"} \u00B7 created by ${s.creator_name}`),
      s.state === "waiting" ? h("div", { class: "field" },
        h("label", {}, "Invite link: send this to the other parties"), h("div", { class: "invite" }, input, copy)) : null);
  }

  function stepper(s) {
    const names = [["1. Setup", "Parties join"], ["2. Input sharing", "Split and encrypt"], ["3. Local sum", "Add your shares"],
      ["4. Share exchange", "Publish partial sum"], ["5. Result", "Reconstruct"]];
    const active = activeStep(s);
    return h("ol", { class: "steps" }, names.map((n, i) =>
      h("li", { class: "step" + (i + 1 < active ? " done" : "") + (i + 1 === active ? " active" : "") }, h("b", {}, n[0]), n[1])));
  }

  function keyBanner(s) {
    if (!s.me || s.state === "done") return null;
    if (ctx.keyStatus === "ok") return null;
    const picker = h("input", { type: "file", accept: ".json,application/json", "aria-label": "Key backup file" });
    picker.addEventListener("change", async () => {
      const f = picker.files && picker.files[0];
      if (!f) return;
      try {
        const entry = await parseBackup(await f.text(), ctx.s);
        await keyStore.set(user.id, ctx.s.id, entry);
        ctx.importError = ""; ctx.partialError = "";
        await refresh(true);
      } catch (e) { ctx.importError = e.message; draw(); }
    });
    const mismatch = ctx.keyStatus === "mismatch";
    return alertBox(mismatch ? "error" : "warn",
      h("strong", {}, mismatch ? "Key mismatch. " : "Your secret key is missing in this browser. "),
      mismatch ? "The key the server lists for you is different from the key saved here. Do not send any numbers. Import your key backup, or contact the session creator."
        : "Without it you cannot read your shares. If you saved a key backup, import it here.",
      h("div", { class: "field" }, picker),
      ctx.importError ? h("div", { class: "small" }, ctx.importError) : null);
  }

  function actionCard(s) {
    const me = s.me;
    const kids = [];
    if (s.state === "waiting") {
      if (!me) {
        kids.push(h("h2", {}, "Join as a party"),
          h("p", {}, "You created this session. Join it to enter your own number."),
          h("a", { class: "btn", href: `#/join/${s.code}` }, "Join this session"));
      } else {
        const left = s.n_parties - s.joined;
        kids.push(h("h2", {}, "Waiting for parties to join"),
          h("p", {}, `You are party ${me.idx}. Waiting for ${partyWord(left)} more. Send them the invite link above.`));
      }
    } else if (s.state === "sharing") {
      if (!me) {
        kids.push(h("h2", {}, "In progress"), h("p", {}, "You created this session but are not a party in it. You can watch the progress here."));
      } else if (me.shares_sent) {
        const sent = s.participants.filter((p) => p.shares_sent).length;
        kids.push(h("h2", {}, "Your encrypted shares are sent"),
          h("p", {}, `Waiting for the other parties: ${sent} of ${s.n_parties} have sent theirs.`));
      } else {
        const input = h("input", { type: "text", id: "value-input", inputmode: "decimal", autocomplete: "off", value: ctx.value,
          placeholder: s.decimals ? "e.g. 5000.50" : "e.g. 5000" });
        input.addEventListener("input", () => { ctx.value = input.value; });
        input.addEventListener("keydown", (ev) => { if (ev.key === "Enter") onSend(); });
        const btn = h("button", { class: "btn", type: "button", disabled: ctx.sending }, ctx.sending ? "Encrypting and sending..." : "Split and send encrypted shares");
        btn.addEventListener("click", onSend);
        kids.push(h("h2", {}, "Enter your private number"),
          h("p", { class: "muted" }, `Your number is split into ${s.n_parties} random pieces in this browser. Piece j is encrypted so only party j can read it. Your real number is never sent.`),
          ctx.formError ? alertBox("error", ctx.formError) : null,
          h("div", { class: "field" }, h("label", { for: "value-input" }, "Your number"), input,
            h("p", { class: "hint" }, s.decimals ? `Up to ${s.decimals} decimal place${s.decimals === 1 ? "" : "s"}. Maximum 1,000,000,000,000.` : "Whole numbers only. Maximum 1,000,000,000,000.")),
          btn);
      }
    } else if (s.state === "summing") {
      if (!me) kids.push(h("h2", {}, "Adding up"), h("p", {}, "The parties are adding their shares. The result appears here soon."));
      else if (me.partial_sent) {
        const done = s.participants.filter((p) => p.partial_sent).length;
        kids.push(h("h2", {}, "Your partial sum is published"), h("p", {}, `Waiting for the other parties: ${done} of ${s.n_parties} are done.`));
      } else if (ctx.partialBusy) {
        kids.push(h("h2", {}, h("span", { class: "spinner", "aria-hidden": "true" }), " Adding up your shares..."),
          h("p", { class: "muted" }, "Your browser is decrypting the shares sent to you and publishing only their sum."));
      } else if (ctx.partialError) {
        const retry = h("button", { class: "btn", type: "button" }, "Try again");
        retry.addEventListener("click", () => { ctx.partialError = ""; maybeAutoPartial(); });
        kids.push(h("h2", {}, "Could not add up your shares"), alertBox("error", ctx.partialError), retry);
      } else {
        kids.push(h("h2", {}, "Adding up"), h("p", { class: "muted" }, "This happens automatically in your browser. Keep this page open."));
      }
    }
    return kids.length ? h("div", { class: "card" }, kids) : null;
  }

  function sharesCard(s) {
    if (!ctx.shares) return null;
    const rows = ctx.shares.shares.map((share, j) => {
      const p = s.participants[j];
      return h("tr", {}, h("td", {}, `Party ${j + 1}${p ? ` (${p.name})` : ""}`), h("td", { class: "mono" }, share));
    });
    return h("div", { class: "card" },
      h("h3", {}, "How your number was split (only you see this)"),
      h("p", { class: "muted small" }, `Your number ${formatScaled(ctx.shares.value, s.decimals)} became ${partyWord(s.n_parties)}\u2019 worth of random-looking pieces. ` +
        "They add up to your number (mod p), but each one alone reveals nothing."),
      h("div", { class: "scroll" }, h("table", { class: "table" },
        h("thead", {}, h("tr", {}, h("th", {}, "Sent to"), h("th", {}, "Share"))), h("tbody", {}, rows))));
  }

  function resultCard(s) {
    if (s.state !== "done" || !s.result) return null;
    const r = s.result;
    const avg = s.metric === "average";
    const note = privacyNote(s.n_parties);
    return h("div", { class: "card dark result" },
      h("div", { class: "label" }, `${avg ? "Average" : "Total"} across ${partyWord(r.parties)}`),
      h("div", { class: "big-number" }, avg ? r.average : r.sum),
      h("div", { class: "label" }, `${avg ? "Total" : "Average"}: ${avg ? r.sum : r.average}`),
      note ? h("p", { class: "label small" }, note)
        : h("p", { class: "label small" }, "No individual number was revealed to the server or to the other parties."));
  }

  function keyCard(s) {
    if (!s.me || ctx.keyStatus !== "ok") return null;
    const btn = h("button", { class: "btn light small", type: "button" }, "Download key backup");
    btn.addEventListener("click", downloadBackup);
    return h("div", { class: "card" }, h("h3", {}, "Your secret key"),
      h("p", { class: "muted small" }, "It lives only in this browser. Download a backup so you can continue from another device or after clearing your browser data. " +
        "Keep the file private: anyone who has it can read the shares sent to you."), btn);
  }

  function participantsCard(s) {
    const rows = s.participants.map((p) => {
      const mine = s.me && p.idx === s.me.idx;
      return h("tr", { class: mine ? "me" : "" },
        h("td", {}, p.idx), h("td", {}, p.name + (mine ? " (you)" : "")),
        h("td", { class: "mono small" }, ctx.fps.get(p.public_key) || ""),
        h("td", {}, h("span", { class: `chip ${p.shares_sent ? "yes" : "no"}` }, p.shares_sent ? "Sent" : "Waiting")),
        h("td", {}, h("span", { class: `chip ${p.partial_sent ? "yes" : "no"}` }, p.partial_sent ? "Published" : "Waiting")));
    });
    for (let i = s.participants.length; i < s.n_parties; i++) {
      rows.push(h("tr", {}, h("td", {}, i + 1), h("td", { class: "muted" }, "Not joined yet"), h("td", {}, ""), h("td", {}, ""), h("td", {}, "")));
    }
    return h("div", { class: "card" }, h("h3", {}, "Parties"),
      h("div", { class: "scroll" }, h("table", { class: "table" },
        h("thead", {}, h("tr", {}, ["#", "Party", "Key fingerprint", "Shares", "Partial sum"].map((t) => h("th", {}, t)))), h("tbody", {}, rows))),
      h("p", { class: "hint" }, "Tip: read your key fingerprint to the other parties (by phone or chat). If everyone sees the same fingerprints for each party, nobody can swap keys in between."));
  }

  function auditCard(s) {
    return h("div", { class: "card" }, h("h3", {}, "Activity log"),
      h("ul", { class: "audit" }, s.audit.slice().reverse().map((e) => h("li", {}, h("time", {}, fmtTime(e.at)), auditText(e)))));
  }

  function privacyDetails() {
    return h("details", { class: "card" }, h("summary", {}, "What can the server see?"),
      h("ul", {},
        h("li", {}, "Your login details, session settings, and each party's public key."),
        h("li", {}, "Encrypted shares: unreadable without the recipient's secret key, which never leaves their browser."),
        h("li", {}, "Each party's partial sum: a random-looking number that reveals nothing alone."),
        h("li", {}, "Never your real number, and never anyone's secret key.")));
  }

  function manageCard(s) {
    const run = (fn) => async () => {
      ctx.manageError = "";
      try { await fn(); } catch (e) { if (e.message !== "cancelled") { ctx.manageError = e.message; draw(); } }
    };
    const btn = (label, cls, fn) => h("button", { class: `btn ${cls} small`, type: "button", onClick: run(fn) }, label);
    const buttons = [];
    if (s.state === "done" && s.result) {
      buttons.push(btn("Download result (CSV)", "light", async () => {
        downloadFile(`securesum-${s.id}-result.csv`, resultCsv(s), "text/csv;charset=utf-8");
      }));
      const q = new URLSearchParams({ title: s.title, n: s.n_parties, metric: s.metric, decimals: s.decimals });
      buttons.push(h("a", { class: "btn light small", href: `#/new?${q.toString()}` }, "Run again with same settings"));
      buttons.push(btn(s.hidden ? "Restore to dashboard" : "Remove from my list", "light", async () => {
        await api("POST", `/api/sessions/${s.id}/${s.hidden ? "unhide" : "hide"}`);
        go("#/");
      }));
    }
    if (s.can_leave) {
      buttons.push(btn("Leave session", "light", async () => {
        if (!confirm("Leave this session? Parties who joined after you will move up one place. You can join again with the invite link.")) throw new Error("cancelled");
        await api("POST", `/api/sessions/${s.id}/leave`);
        go("#/");
      }));
    }
    if (s.can_delete) {
      buttons.push(btn("Delete session", "danger", async () => {
        const warn = s.state === "done" ? "The result will be lost for all parties." : s.state === "waiting" ? "The invite link stops working." : "This cancels the run for all parties.";
        if (!confirm(`Delete "${s.title}" for everyone? ${warn} This cannot be undone.`)) throw new Error("cancelled");
        await api("DELETE", `/api/sessions/${s.id}`);
        go("#/");
      }));
    }
    buttons.push(h("a", { class: "btn light small", href: "#/" }, "Back to dashboard"));
    return h("div", { class: "card" }, h("h3", {}, "Manage"),
      s.state === "done" ? h("p", { class: "muted small" }, "This session is finished. You can download the result, run it again, or remove it from your list.") : null,
      ctx.manageError ? alertBox("error", ctx.manageError) : null,
      h("div", { class: "row" }, buttons));
  }

  function draw() {
    const s = ctx.s;
    if (!s) return;
    const active = document.activeElement;
    const keepFocus = !!(active && active.id === "value-input");
    const caret = keepFocus ? active.selectionStart : null;
    const note = privacyNote(s.n_parties);
    view.replaceChildren(
      headerCard(s), stepper(s),
      note && s.state !== "done" ? alertBox("warn", note) : null,
      keyBanner(s), actionCard(s), sharesCard(s), resultCard(s), manageCard(s), keyCard(s),
      participantsCard(s), auditCard(s), privacyDetails());
    if (keepFocus) {
      const el = document.getElementById("value-input");
      if (el) { el.focus(); try { el.setSelectionRange(caret, caret); } catch (e) { /* ignore */ } }
    }
  }

  await refresh(true);
  if (!isCurrent()) return;
  timer = setInterval(() => {
    if (!document.hidden && ctx.s && ctx.s.state !== "done") refresh(false);
  }, 3000);
  cleanups.push(() => clearInterval(timer));
}

// ------------------------------------------------------------------ account
let accountNotice = "";

async function accountView(isCurrent) {
  user = (await api("GET", "/api/me")).user;
  const devices = (await api("GET", "/api/account/devices")).devices;
  if (!isCurrent()) return;
  const notice = accountNotice; accountNotice = "";
  const again = (msg) => { accountNotice = msg; route(); };
  const mk = () => ({ err: h("div", { class: "alert error hidden", role: "alert" }), ok: h("div", { class: "alert ok hidden", role: "status" }) });
  const guarded = (m, btn, fn) => async (ev) => {
    ev.preventDefault(); m.err.classList.add("hidden"); m.ok.classList.add("hidden"); btn.disabled = true;
    try { await fn(); } catch (e) { showError(m.err, e.message); } finally { btn.disabled = false; }
  };
  const chip = (text, on) => h("span", { class: `chip ${on ? "yes" : "no"}` }, text);

  // ---- profile
  const pm = mk();
  const nameIn = h("input", { type: "text", id: "profile-name", value: user.name, maxlength: 60, required: true });
  const pbtn = h("button", { class: "btn", type: "submit" }, "Save");
  const profile = h("div", { class: "card" }, h("h3", {}, "Profile"),
    h("div", { class: "row" }, h("span", { class: "avatar big", "aria-hidden": "true" }, initials(user.name)),
      h("div", {}, h("strong", {}, user.email), " ", chip(user.email_verified ? "Verified" : "Not verified", user.email_verified),
        h("div", { class: "muted small" }, `Member since ${fmtTime(user.created_at)}`))),
    pm.err, pm.ok,
    h("form", { onSubmit: guarded(pm, pbtn, async () => { await api("POST", "/api/account/name", { name: nameIn.value }); again("Name saved."); }) },
      h("div", { class: "field" }, h("label", { for: "profile-name" }, "Your name or company"), nameIn), pbtn));

  // ---- email change
  const em = mk();
  const emailBox = h("div", {});
  function emailStep1() {
    const nf = field("New email address", "email", "new-email", "email", { maxlength: 120 });
    const pf = field("Your password (to confirm it is you)", "password", "email-password", "current-password");
    const btn = h("button", { class: "btn", type: "submit" }, "Send code to new address");
    emailBox.replaceChildren(h("form", { onSubmit: guarded(em, btn, async () => {
      const r = await api("POST", "/api/account/email/request", { new_email: nf.input.value, password: pf.input.value });
      emailStep2(r.new_email);
    }) }, nf.wrap, pf.wrap, btn));
  }
  function emailStep2(newEmail) {
    const cf = field("6-digit code", "text", "email-code", "one-time-code", { inputmode: "numeric", maxlength: 6, pattern: "[0-9]{6}" });
    const btn = h("button", { class: "btn", type: "submit" }, "Confirm new email");
    emailBox.replaceChildren(h("p", { class: "muted" }, "We sent a code to ", h("strong", {}, newEmail), ". Your email changes only after you enter it."),
      consoleHint(),
      h("form", { onSubmit: guarded(em, btn, async () => {
        await api("POST", "/api/account/email/confirm", { new_email: newEmail, code: cf.input.value.trim() });
        again(`Your email is now ${newEmail}.`);
      }) }, cf.wrap, h("div", { class: "row" }, btn, h("button", { class: "btn light", type: "button", onClick: emailStep1 }, "Start over"))));
  }
  if (!user.google_linked) emailStep1();
  const emailCard = h("div", { class: "card" }, h("h3", {}, "Email address"),
    user.google_linked ? h("p", { class: "muted" }, "Your email comes from your Google account, so it cannot be changed here.") : [em.err, em.ok, emailBox]);

  // ---- password
  const wm = mk();
  const passBox = h("div", {});
  function changePasswordForm() {
    const o = field("Current password", "password", "old-password", "current-password");
    const n1 = field("New password (at least 8 characters)", "password", "new-password", "new-password", { minlength: 8, maxlength: 200 });
    const n2 = field("Repeat new password", "password", "new-password2", "new-password");
    const btn = h("button", { class: "btn", type: "submit" }, "Change password");
    passBox.replaceChildren(h("form", { onSubmit: guarded(wm, btn, async () => {
      if (n1.input.value !== n2.input.value) throw new Error("The two new passwords do not match.");
      await api("POST", "/api/auth/password", { old_password: o.input.value, new_password: n1.input.value });
      o.input.value = ""; n1.input.value = ""; n2.input.value = "";
      showError(wm.ok, "Password changed. You were signed out on all other devices.");
    }) }, o.wrap, n1.wrap, n2.wrap, btn));
  }
  function setPasswordStart() {
    const btn = h("button", { class: "btn", type: "button" }, "Send me a code");
    btn.addEventListener("click", async () => {
      wm.err.classList.add("hidden"); btn.disabled = true;
      try { await api("POST", "/api/auth/forgot", { email: user.email }); setPasswordCode(); }
      catch (e) { showError(wm.err, e.message); btn.disabled = false; }
    });
    passBox.replaceChildren(h("p", { class: "muted" }, "You signed in with Google, so this account has no password yet. Add one to also log in with your email. We will send a code to confirm it is you."), btn);
  }
  function setPasswordCode() {
    const c = field("6-digit code", "text", "set-code", "one-time-code", { inputmode: "numeric", maxlength: 6, pattern: "[0-9]{6}" });
    const n1 = field("New password (at least 8 characters)", "password", "new-password", "new-password", { minlength: 8, maxlength: 200 });
    const n2 = field("Repeat new password", "password", "new-password2", "new-password");
    const btn = h("button", { class: "btn", type: "submit" }, "Set password");
    passBox.replaceChildren(consoleHint(), h("p", { class: "muted" }, "Setting a password signs you out everywhere, so you will log in again afterwards."),
      h("form", { onSubmit: guarded(wm, btn, async () => {
        if (n1.input.value !== n2.input.value) throw new Error("The two passwords do not match.");
        await api("POST", "/api/auth/reset", { email: user.email, code: c.input.value.trim(), new_password: n1.input.value });
        clearAuth(); flash = "Password set. You can now log in with your email and password, or with Google."; go("#/login");
      }) }, c.wrap, n1.wrap, n2.wrap, btn));
  }
  if (user.has_password) changePasswordForm(); else setPasswordStart();
  const passCard = h("div", { class: "card" }, h("h3", {}, user.has_password ? "Change password" : "Add a password"), wm.err, wm.ok, passBox);

  // ---- sign-in methods
  const methods = h("div", { class: "card" }, h("h3", {}, "Ways to sign in"),
    h("ul", { class: "methods" },
      h("li", {}, h("span", {}, "Email and password"), chip(user.has_password ? "On" : "Not set", user.has_password)),
      h("li", {}, h("span", {}, "Google"), chip(user.google_linked ? "Connected" : "Not connected", user.google_linked))),
    user.google_linked ? null : h("p", { class: "hint" }, "To connect Google, log out and use \u201CContinue with Google\u201D with the same email address."));

  // ---- devices
  const dm = mk();
  const others = devices.filter((d) => !d.current);
  const deviceCard = h("div", { class: "card" }, h("h3", {}, "Where you are logged in"), dm.err, dm.ok,
    h("ul", { class: "devices" }, devices.map((d) => h("li", { class: "device" },
      h("div", {}, h("strong", {}, describeAgent(d.user_agent)), d.current ? [" ", chip("This device", true)] : null,
        h("div", { class: "muted small" }, d.last_used ? `Last active ${fmtTime(d.last_used)}` : "Last active: unknown")),
      d.current ? null : h("button", { class: "btn light small", type: "button", onClick: async () => {
        try { await api("POST", "/api/account/devices/revoke", { id: d.id }); again("That device was logged out."); }
        catch (e) { showError(dm.err, e.message); }
      } }, "Log out")))),
    others.length ? h("button", { class: "btn light small", type: "button", onClick: async () => {
      try { await api("POST", "/api/account/devices/revoke-others"); again("All other devices were logged out."); }
      catch (e) { showError(dm.err, e.message); }
    } }, "Log out all other devices") : null);

  // ---- keys
  const keys = h("div", { class: "card" }, h("h3", {}, "Your secret keys"),
    h("p", { class: "muted" }, "Each session you join has its own secret key, stored only in this browser. Logging out does not delete it, so you can continue later. " +
      "Download a key backup from each session page if you want to continue on another device."));

  // ---- delete account
  const xm = mk();
  const delPw = field("Your password", "password", "delete-password", "current-password");
  const delBtn = h("button", { class: "btn danger", type: "submit" }, "Delete my account");
  const danger = h("div", { class: "card danger-zone" }, h("h3", {}, "Delete account"),
    h("p", { class: "muted" }, "This logs you out everywhere and closes your account for good. Finished sessions stay visible to the other parties, with your name shown as \u201CDeleted user\u201D. " +
      "You cannot delete your account while you are part of a session that is not finished."),
    xm.err,
    user.has_password
      ? h("form", { onSubmit: guarded(xm, delBtn, async () => {
        if (!confirm("Delete your account permanently? This cannot be undone.")) return;
        await api("POST", "/api/account/delete", { password: delPw.input.value });
        clearAuth(); flash = "Your account was deleted."; go("#/login");
      }) }, delPw.wrap, delBtn)
      : h("p", { class: "hint" }, "Add a password above first, then you can delete your account."));

  shell(h("div", {}, h("h1", {}, "Account settings"), notice ? alertBox("ok", notice) : null,
    profile, emailCard, passCard, methods, deviceCard, keys, danger));
}

// ------------------------------------------------------------------ start
window.addEventListener("hashchange", route);
route();

export { handleGoogleCredential, resultCsv };   // exported so the tests can check the CSV contents
