<?php
// Planetary Distance-Based Auth (Prototype)
// NOT for production use. TLS required in real deployments.

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');

$raw = file_get_contents('php://input');
$data = json_decode($raw, true);

if (!is_array($data)) {
    http_response_code(400);
    echo json_encode(['ok' => false, 'message' => 'Invalid request.']);
    exit;
}

$action = isset($data['action']) ? trim($data['action']) : '';
$username = isset($data['username']) ? trim($data['username']) : '';
$planet = isset($data['planet']) ? strtolower(trim($data['planet'])) : '';
$pin = isset($data['pin']) ? trim($data['pin']) : '';
$ts = isset($data['ts']) ? intval($data['ts']) : 0;
$hash = isset($data['hash']) ? strtolower(trim($data['hash'])) : '';

// SQLite user store (prototype)
$dbPath = __DIR__ . DIRECTORY_SEPARATOR . 'auth.db';
try {
    $pdo = new PDO('sqlite:' . $dbPath);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['ok' => false, 'message' => 'Database connection error.']);
    exit;
}

// Ensure schema
$pdo->exec('CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    seal TEXT,
    created_at TEXT NOT NULL
)');
// Sessions table
$pdo->exec('CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    token TEXT NOT NULL,
    created_at TEXT NOT NULL
)');

$cols = $pdo->query("PRAGMA table_info(users)")->fetchAll(PDO::FETCH_ASSOC);
$hasSeal = false;
foreach ($cols as $c) {
    if (isset($c['name']) && $c['name'] === 'seal') {
        $hasSeal = true;
        break;
    }
}
if (!$hasSeal) {
    $pdo->exec('ALTER TABLE users ADD COLUMN seal TEXT');
}

if ($action === 'enroll_device') {
    $seal = isset($data['seal']) ? strtolower(trim($data['seal'])) : '';
    $token = isset($data['token']) ? trim($data['token']) : '';

    if ($username === '' || $seal === '' || $token === '') {
        http_response_code(400);
        echo json_encode(['ok' => false, 'message' => 'Missing fields.']);
        exit;
    }
    if (!preg_match('/^[0-9a-f]{64}$/', $seal)) {
        http_response_code(400);
        echo json_encode(['ok' => false, 'message' => 'Invalid seal.']);
        exit;
    }

    $stmt = $pdo->prepare('SELECT id FROM sessions WHERE username = :u AND token = :t LIMIT 1');
    $stmt->execute([':u' => $username, ':t' => $token]);
    $sess = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$sess) {
        http_response_code(403);
        echo json_encode(['ok' => false, 'message' => 'Invalid session.']);
        exit;
    }

    // Prevent re-enrollment if seal already exists
    $stmt = $pdo->prepare('SELECT seal FROM users WHERE username = :u LIMIT 1');
    $stmt->execute([':u' => $username]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$row) {
        http_response_code(403);
        echo json_encode(['ok' => false, 'message' => 'User not found.']);
        exit;
    }
    if (isset($row['seal']) && $row['seal'] !== '') {
        http_response_code(409);
        echo json_encode(['ok' => false, 'message' => 'Device already enrolled.']);
        exit;
    }

    $stmt = $pdo->prepare('UPDATE users SET seal = :s WHERE username = :u');
    $stmt->execute([':s' => $seal, ':u' => $username]);

    echo json_encode(['ok' => true, 'message' => 'Seal saved.']);
    exit;
}

if ($action === 'register_user') {
    $password = isset($data['password']) ? $data['password'] : '';
    if ($username === '' || $password === '') {
        http_response_code(400);
        echo json_encode(['ok' => false, 'message' => 'Missing fields.']);
        exit;
    }

    $stmt = $pdo->prepare('INSERT INTO users (username, password, created_at) VALUES (:u, :p, :c)');
    try {
        $stmt->execute([':u' => $username, ':p' => $password, ':c' => date('c')]);
        echo json_encode(['ok' => true, 'message' => 'Registration successful. Please login.']);
    } catch (Exception $e) {
        http_response_code(409);
        echo json_encode(['ok' => false, 'message' => 'User already exists.']);
    }
    exit;
}

if ($username === '' || $planet === '' || $pin === '' || $ts <= 0 || $hash === '') {
    http_response_code(400);
    echo json_encode(['ok' => false, 'message' => 'Missing fields.']);
    exit;
}
if (!preg_match('/^[0-9]{4}$/', $pin)) {
    http_response_code(400);
    echo json_encode(['ok' => false, 'message' => 'PIN must be exactly 4 digits.']);
    exit;
}

$stmt = $pdo->prepare('SELECT password, seal FROM users WHERE username = :u LIMIT 1');
$stmt->execute([':u' => $username]);
$row = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$row) {
    http_response_code(403);
    echo json_encode(['ok' => false, 'message' => 'User not found.']);
    exit;
}

$PLANETS = [
    'mars' => ['name' => 'Mars', 'a' => 1.523679, 'e' => 0.0934, 'period' => 686.98, 'phase' => 0.6],
    'venus' => ['name' => 'Venus', 'a' => 0.723332, 'e' => 0.0068, 'period' => 224.70, 'phase' => 1.2],
    'jupiter' => ['name' => 'Jupiter', 'a' => 5.2044, 'e' => 0.0489, 'period' => 4332.59, 'phase' => 2.4],
    'saturn' => ['name' => 'Saturn', 'a' => 9.5826, 'e' => 0.0565, 'period' => 10759.22, 'phase' => 0.9]
];

if (!isset($PLANETS[$planet])) {
    http_response_code(400);
    echo json_encode(['ok' => false, 'message' => 'Invalid planet.']);
    exit;
}

$AU_KM = 149597870.7;
$J2000 = 946684800; // 2000-01-01 00:00:00 UTC

function planetDistanceKm($planetKey, $ts, $PLANETS, $AU_KM, $J2000) {
    $p = $PLANETS[$planetKey];
    $days = ($ts - $J2000) / 86400.0;
    $M = 2 * M_PI * ($days / $p['period']) + $p['phase'];
    $rPlanet = $p['a'] * (1 - $p['e'] * cos($M));

    $aE = 1.0000; $eE = 0.0167; $periodE = 365.256; $phaseE = 0.0;
    $ME = 2 * M_PI * ($days / $periodE) + $phaseE;
    $rEarth = $aE * (1 - $eE * cos($ME));

    $angle = abs($M - $ME);
    $dAU = sqrt($rEarth*$rEarth + $rPlanet*$rPlanet - 2*$rEarth*$rPlanet*cos($angle));
    return $dAU * $AU_KM;
}

function sha512hex($s) {
    return hash('sha512', $s);
}

$pwd = $row['password'];
$seal = isset($row['seal']) ? $row['seal'] : '';
$hasSeal = ($seal !== '' && $seal !== null);
$ok = false;
$okDistance = 0.0;
$okPlanetName = $PLANETS[$planet]['name'];

// Tolerance window: +-2 seconds
for ($dt = -2; $dt <= 2; $dt++) {
    $t = $ts + $dt;
    $shiftSeconds = intval($pin) * 60;
    $shiftedTs = $t - $shiftSeconds;
    $dist = planetDistanceKm($planet, $shiftedTs, $PLANETS, $AU_KM, $J2000);
    $distFixed = number_format($dist, 3, '.', '');
    if ($hasSeal) {
        $calc = sha512hex($pwd . $distFixed . $seal);
    } else {
        $calc = sha512hex($pwd . $distFixed);
    }

    if (hash_equals($calc, $hash)) {
        $ok = true;
        $okDistance = $dist;
        break;
    }
}

if ($ok) {
    $token = bin2hex(random_bytes(16));
    $stmt = $pdo->prepare('INSERT INTO sessions (username, token, created_at) VALUES (:u, :t, :c)');
    $stmt->execute([':u' => $username, ':t' => $token, ':c' => date('c')]);
    $msg = "Login successful: {$okPlanetName} is currently " . number_format($okDistance, 3, '.', '') . " km away";
    echo json_encode(['ok' => true, 'message' => $msg, 'token' => $token, 'needsEnroll' => !$hasSeal]);
    exit;
}

http_response_code(403);
echo json_encode(['ok' => false, 'message' => 'Login failed']);
