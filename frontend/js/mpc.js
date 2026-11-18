// Secret-sharing math (additive sharing modulo a public prime p). Pure BigInt.
export const MAX_SCALED_VALUE = 10n ** 15n;

export function randomBelow(p) {
  // Uniform in [0, p) using rejection sampling on 64 random bits.
  const limit = (1n << 64n) - ((1n << 64n) % p);
  for (;;) {
    const a = new Uint8Array(8);
    globalThis.crypto.getRandomValues(a);
    let x = 0n;
    for (const b of a) x = (x << 8n) | BigInt(b);
    if (x < limit) return x % p;
  }
}

// Split `value` into n shares that add up to value (mod p). Any n-1 shares look random.
export function splitSecret(value, n, p) {
  if (n < 1) throw new Error("n must be at least 1");
  const shares = [];
  let acc = 0n;
  for (let i = 0; i < n - 1; i++) {
    const r = randomBelow(p);
    shares.push(r);
    acc = (acc + r) % p;
  }
  shares.push((((value - acc) % p) + p) % p);
  return shares;
}

export function sumMod(list, p) {
  return list.reduce((a, b) => (a + b) % p, 0n);
}

// "1234.56" with decimals=2  ->  123456n. Rejects bad input with a friendly message.
export function parseScaled(input, decimals, max = MAX_SCALED_VALUE) {
  const text = String(input ?? "").trim();
  if (!/^\d+(\.\d+)?$/.test(text)) {
    throw new Error("Enter a number like 5000 or 5000.50 (no negative values or letters).");
  }
  const [whole, frac = ""] = text.split(".");
  if (frac.length > decimals) {
    throw new Error(
      decimals === 0
        ? "This session uses whole numbers only."
        : `This session allows at most ${decimals} decimal place${decimals === 1 ? "" : "s"}.`
    );
  }
  const scaled = BigInt(whole) * 10n ** BigInt(decimals) + BigInt(frac.padEnd(decimals, "0") || "0");
  if (scaled > max) throw new Error("That number is too large for this session.");
  return scaled;
}
