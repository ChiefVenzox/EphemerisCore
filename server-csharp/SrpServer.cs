// CiftOnay-PAKE v1 server (C# .NET)
using System;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace CiftOnayPake {
    public static class SrpCommon {
        public const string N_HEX =
            "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050" +
            "A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50" +
            "E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B8" +
            "55F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773B" +
            "CA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748" +
            "544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6" +
            "AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6" +
            "94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73";
        public const int g = 2;

        public static BigInteger N => BigInteger.Parse("0" + N_HEX, System.Globalization.NumberStyles.HexNumber);

        public static byte[] HexToBytes(string hex) {
            if (hex.Length % 2 != 0) hex = "0" + hex;
            byte[] bytes = new byte[hex.Length / 2];
            for (int i = 0; i < bytes.Length; i++) {
                bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            }
            return bytes;
        }

        public static string BytesToHex(byte[] bytes) {
            var sb = new StringBuilder(bytes.Length * 2);
            foreach (var b in bytes) sb.Append(b.ToString("x2"));
            return sb.ToString();
        }

        public static string PadHex(string hex) {
            return hex.PadLeft(N_HEX.Length, '0');
        }

        public static byte[] H(byte[] data) {
            using var sha = SHA512.Create();
            return sha.ComputeHash(data);
        }

        public static BigInteger HInt(byte[] data) {
            return BigInteger.Parse("0" + BytesToHex(H(data)), System.Globalization.NumberStyles.HexNumber);
        }

        public static BigInteger k() {
            var nBytes = HexToBytes(N_HEX);
            var gBytes = HexToBytes(PadHex(g.ToString("x")));
            return HInt(Concat(nBytes, gBytes));
        }

        public static byte[] Concat(params byte[][] arrays) {
            int len = 0; foreach (var a in arrays) len += a.Length;
            var res = new byte[len];
            int off = 0;
            foreach (var a in arrays) { Buffer.BlockCopy(a, 0, res, off, a.Length); off += a.Length; }
            return res;
        }

        public static string RandHex(int bytes) {
            var b = new byte[bytes];
            RandomNumberGenerator.Fill(b);
            return BytesToHex(b);
        }
    }

    public class SrpServer {
        public static string CreateSalt(int bytes = 16) => SrpCommon.RandHex(bytes);

        public static string CreateVerifier(string I, string P, string saltHex) {
            var h1 = SrpCommon.H(Encoding.UTF8.GetBytes(I + ":" + P));
            var xH = SrpCommon.H(SrpCommon.Concat(SrpCommon.HexToBytes(saltHex), h1));
            var x = BigInteger.Parse("0" + SrpCommon.BytesToHex(xH), System.Globalization.NumberStyles.HexNumber);
            var v = BigInteger.ModPow(new BigInteger(SrpCommon.g), x, SrpCommon.N);
            return v.ToString("x");
        }

        public static Session Challenge(string I, string Ahex, string saltHex, string vHex) {
            var N = SrpCommon.N;
            var g = new BigInteger(SrpCommon.g);
            var k = SrpCommon.k();

            var A = BigInteger.Parse("0" + Ahex, System.Globalization.NumberStyles.HexNumber);
            var v = BigInteger.Parse("0" + vHex, System.Globalization.NumberStyles.HexNumber);
            var b = BigInteger.Parse("0" + SrpCommon.RandHex(32), System.Globalization.NumberStyles.HexNumber);

            var B = (k * v + BigInteger.ModPow(g, b, N)) % N;
            var serverNonce = SrpCommon.RandHex(16);

            var u = SrpCommon.HInt(SrpCommon.Concat(
                SrpCommon.HexToBytes(SrpCommon.PadHex(Ahex)),
                SrpCommon.HexToBytes(SrpCommon.PadHex(B.ToString("x")))
            ));

            return new Session {
                Salt = saltHex,
                B = B.ToString("x"),
                ServerNonce = serverNonce,
                A = Ahex,
                V = vHex,
                U = u.ToString("x"),
                BPriv = b.ToString("x")
            };
        }

        public static VerifyResult Verify(Session s, string clientNonceHex, string M1hex, string idPattern) {
            var N = SrpCommon.N;
            var A = BigInteger.Parse("0" + s.A, System.Globalization.NumberStyles.HexNumber);
            var v = BigInteger.Parse("0" + s.V, System.Globalization.NumberStyles.HexNumber);
            var u = BigInteger.Parse("0" + s.U, System.Globalization.NumberStyles.HexNumber);
            var b = BigInteger.Parse("0" + s.BPriv, System.Globalization.NumberStyles.HexNumber);

            var S = BigInteger.ModPow(A * BigInteger.ModPow(v, u, N), b, N);
            var K = SrpCommon.H(SrpCommon.HexToBytes(SrpCommon.PadHex(S.ToString("x"))));

            var msg = SrpCommon.Concat(
                SrpCommon.HexToBytes(clientNonceHex),
                SrpCommon.HexToBytes(s.ServerNonce),
                Encoding.UTF8.GetBytes(idPattern ?? ""),
                SrpCommon.HexToBytes(SrpCommon.PadHex(s.A)),
                SrpCommon.HexToBytes(SrpCommon.PadHex(s.B))
            );

            using var hmac = new HMACSHA512(K);
            var M1 = SrpCommon.BytesToHex(hmac.ComputeHash(msg));

            if (!string.Equals(M1, M1hex, StringComparison.OrdinalIgnoreCase)) {
                return new VerifyResult { Ok = false };
            }

            var msg2 = SrpCommon.Concat(
                Encoding.UTF8.GetBytes("OK"),
                SrpCommon.HexToBytes(clientNonceHex),
                SrpCommon.HexToBytes(s.ServerNonce),
                SrpCommon.HexToBytes(SrpCommon.PadHex(s.A)),
                SrpCommon.HexToBytes(SrpCommon.PadHex(s.B))
            );

            var M2 = SrpCommon.BytesToHex(hmac.ComputeHash(msg2));
            return new VerifyResult { Ok = true, M2 = M2 };
        }
    }

    public class Session {
        public string Salt { get; set; }
        public string B { get; set; }
        public string ServerNonce { get; set; }
        public string A { get; set; }
        public string V { get; set; }
        public string U { get; set; }
        public string BPriv { get; set; }
    }

    public class VerifyResult {
        public bool Ok { get; set; }
        public string M2 { get; set; }
    }
}
