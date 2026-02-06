// CiftOnay-PAKE v1 client (browser WebCrypto + BigInt)
// Requires: window.crypto.subtle, BigInt

const N_HEX = "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050" +
  "A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50" +
  "E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B8" +
  "55F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773B" +
  "CA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748" +
  "544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6" +
  "AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6" +
  "94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73";
const g = 2n;
const N = BigInt("0x" + N_HEX);

function hexToBytes(hex) {
  if (hex.length % 2 !== 0) hex = "0" + hex;
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return out;
}

function bytesToHex(bytes) {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}

function padHex(hex) {
  const len = N_HEX.length;
  return hex.padStart(len, "0");
}

function bigIntToHex(bi) {
  let hex = bi.toString(16);
  if (hex.length % 2 !== 0) hex = "0" + hex;
  return hex;
}

function modPow(base, exp, mod) {
  let result = 1n;
  let b = base % mod;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % mod;
    e >>= 1n;
    b = (b * b) % mod;
  }
  return result;
}

function concatBytes(...arrays) {
  let len = 0;
  for (const a of arrays) len += a.length;
  const out = new Uint8Array(len);
  let off = 0;
  for (const a of arrays) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

async function sha512(bytes) {
  const buf = await crypto.subtle.digest("SHA-512", bytes);
  return new Uint8Array(buf);
}

async function hmacSha512(keyBytes, dataBytes) {
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-512" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, dataBytes);
  return new Uint8Array(sig);
}

async function H(...parts) {
  return sha512(concatBytes(...parts));
}

async function H_hex(...parts) {
  return bytesToHex(await H(...parts));
}

async function H_int(...parts) {
  const hex = await H_hex(...parts);
  return BigInt("0x" + hex);
}

async function computeK() {
  const nBytes = hexToBytes(N_HEX);
  const gBytes = hexToBytes(padHex(g.toString(16)));
  return H_int(nBytes, gBytes);
}

export class SrpClient {
  constructor(username, password, idPattern) {
    this.I = username;
    this.P = password;
    this.idPattern = idPattern || "";
    this.a = null;
    this.A = null;
    this.clientNonce = null;
  }

  async begin() {
    // 256-bit a
    const aBytes = new Uint8Array(32);
    crypto.getRandomValues(aBytes);
    this.a = BigInt("0x" + bytesToHex(aBytes));
    this.A = modPow(g, this.a, N);

    const cn = new Uint8Array(16);
    crypto.getRandomValues(cn);
    this.clientNonce = bytesToHex(cn);

    return { A: bigIntToHex(this.A), clientNonce: this.clientNonce };
  }

  async computeM1(saltHex, Bhex, serverNonceHex) {
    const k = await computeK();
    const B = BigInt("0x" + Bhex);

    const H1 = await H(new TextEncoder().encode(this.I + ":" + this.P));
    const xH = await H(hexToBytes(saltHex), H1);
    const x = BigInt("0x" + bytesToHex(xH));

    const u = await H_int(hexToBytes(padHex(this.A.toString(16))), hexToBytes(padHex(Bhex)));

    const gx = modPow(g, x, N);
    const base = (B - (k * gx) % N + N) % N;
    const exp = (this.a + u * x) % (N - 1n);
    const S = modPow(base, exp, N);
    const K = await H(hexToBytes(padHex(S.toString(16))));
    this.S = S;
    this.K = K;

    const msg = concatBytes(
      hexToBytes(this.clientNonce),
      hexToBytes(serverNonceHex),
      new TextEncoder().encode(this.idPattern),
      hexToBytes(padHex(this.A.toString(16))),
      hexToBytes(padHex(Bhex))
    );

    const M1 = await hmacSha512(K, msg);
    return { M1: bytesToHex(M1), clientNonce: this.clientNonce };
  }

  async verifyM2(M2hex, serverNonceHex, Bhex) {
    const K = this.K;
    const msg = concatBytes(
      new TextEncoder().encode("OK"),
      hexToBytes(this.clientNonce),
      hexToBytes(serverNonceHex),
      hexToBytes(padHex(this.A.toString(16))),
      hexToBytes(padHex(Bhex))
    );
    const M2 = await hmacSha512(K, msg);
    return bytesToHex(M2) === M2hex;
  }
}

export async function createVerifier(username, password, saltHex) {
  const H1 = await H(new TextEncoder().encode(username + ":" + password));
  const xH = await H(hexToBytes(saltHex), H1);
  const x = BigInt("0x" + bytesToHex(xH));
  const v = modPow(g, x, N);
  return { verifier: bigIntToHex(v) };
}
