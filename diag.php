<?php
header('Content-Type: text/plain; charset=utf-8');

$dbPath = __DIR__ . DIRECTORY_SEPARATOR . 'auth.db';
try {
    $pdo = new PDO('sqlite:' . $dbPath);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (Exception $e) {
    echo "DB error\n";
    exit;
}

$username = isset($_GET['u']) ? trim($_GET['u']) : '';
if ($username === '') {
    echo "Usage: diag.php?u=username\n";
    exit;
}

$stmt = $pdo->prepare('SELECT username, password, seal, created_at FROM users WHERE username = :u LIMIT 1');
$stmt->execute([':u' => $username]);
$row = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$row) {
    echo "User not found\n";
    exit;
}

$seal = $row['seal'];
$sealStatus = ($seal === null || $seal === '') ? 'EMPTY' : 'SET';
$sealLen = ($seal === null) ? 0 : strlen($seal);

echo "username: " . $row['username'] . "\n";
echo "password: (stored)\n";
echo "seal: " . $sealStatus . " (len=" . $sealLen . ")\n";
echo "created_at: " . $row['created_at'] . "\n";
