<?php
// CiftOnay-PAKE v1 server (PHP + GMP)

class SrpCommon {
    public static string $N_HEX = "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050" .
        "A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50" .
        "E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B8" .
        "55F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773B" .
        "CA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748" .
        "544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6" .
        "AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6" .
        "94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73";
    public static int $g = 2;

    public static function N(): 
        GMP { return gmp_init(self::$N_HEX, 16); }

    public static function padHex(string $hex): string {
        $len = strlen(self::$N_HEX);
        return str_pad($hex, $len, "0", STR_PAD_LEFT);
    }

    public static function hexToBin(string $hex): string {
        if (strlen($hex) % 2 !== 0) $hex = "0" . $hex;
        return hex2bin($hex);
    }

    public static function H(string $data): string {
        return hash("sha512", $data, true);
    }

    public static function H_hex(string $data): string {
        return hash("sha512", $data, false);
    }

    public static function H_int(string $data): GMP {
        return gmp_init(self::H_hex($data), 16);
    }

    public static function k(): GMP {
        $nBytes = self::hexToBin(self::$N_HEX);
        $gBytes = self::hexToBin(self::padHex(dechex(self::$g)));
        return self::H_int($nBytes . $gBytes);
    }

    public static function gmpHex(GMP $n): string {
        return gmp_strval($n, 16);
    }
}

class SrpServer {
    public static function createSalt(int $bytes = 16): string {
        return bin2hex(random_bytes($bytes));
    }

    public static function createVerifier(string $I, string $P, string $saltHex): string {
        $H1 = SrpCommon::H($I . ":" . $P);
        $xH = SrpCommon::H(SrpCommon::hexToBin($saltHex) . $H1);
        $x = gmp_init(bin2hex($xH), 16);
        $v = gmp_powm(gmp_init(SrpCommon::$g, 10), $x, SrpCommon::N());
        return SrpCommon::gmpHex($v);
    }

    // Challenge step
    public static function challenge(string $I, string $Ahex, string $saltHex, string $vHex): array {
        $N = SrpCommon::N();
        $g = gmp_init(SrpCommon::$g, 10);
        $k = SrpCommon::k();

        $A = gmp_init($Ahex, 16);
        $v = gmp_init($vHex, 16);
        $b = gmp_init(bin2hex(random_bytes(32)), 16);

        $B = gmp_mod(gmp_add(gmp_mul($k, $v), gmp_powm($g, $b, $N)), $N);
        $serverNonce = bin2hex(random_bytes(16));

        $u = SrpCommon::H_int(
            SrpCommon::hexToBin(SrpCommon::padHex($Ahex)) .
            SrpCommon::hexToBin(SrpCommon::padHex(SrpCommon::gmpHex($B)))
        );

        return [
            "salt" => $saltHex,
            "B" => SrpCommon::gmpHex($B),
            "serverNonce" => $serverNonce,
            "b" => SrpCommon::gmpHex($b),
            "u" => SrpCommon::gmpHex($u),
            "v" => $vHex,
            "A" => $Ahex
        ];
    }

    // Verify client proof
    public static function verify(array $session, string $clientNonceHex, string $M1hex, string $idPattern): array {
        $N = SrpCommon::N();
        $A = gmp_init($session["A"], 16);
        $v = gmp_init($session["v"], 16);
        $u = gmp_init($session["u"], 16);
        $b = gmp_init($session["b"], 16);
        $Bhex = $session["B"];
        $serverNonceHex = $session["serverNonce"];

        $S = gmp_powm(gmp_mul($A, gmp_powm($v, $u, $N)), $b, $N);
        $K = SrpCommon::H(SrpCommon::hexToBin(SrpCommon::padHex(SrpCommon::gmpHex($S))));

        $msg =
            SrpCommon::hexToBin($clientNonceHex) .
            SrpCommon::hexToBin($serverNonceHex) .
            $idPattern .
            SrpCommon::hexToBin(SrpCommon::padHex($session["A"])) .
            SrpCommon::hexToBin(SrpCommon::padHex($Bhex));

        $M1 = hash_hmac("sha512", $msg, $K, false);

        $ok = hash_equals($M1, strtolower($M1hex));
        if (!$ok) {
            return ["ok" => false];
        }

        $msg2 =
            "OK" .
            SrpCommon::hexToBin($clientNonceHex) .
            SrpCommon::hexToBin($serverNonceHex) .
            SrpCommon::hexToBin(SrpCommon::padHex($session["A"])) .
            SrpCommon::hexToBin(SrpCommon::padHex($Bhex));

        $M2 = hash_hmac("sha512", $msg2, $K, false);
        return ["ok" => true, "M2" => $M2];
    }
}
