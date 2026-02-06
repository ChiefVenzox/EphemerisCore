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
$seal = isset($_GET['seal']) ? strtolower(trim($_GET['seal'])) : '';

if ($username === '' || $seal === '') {
    echo "Usage: fix_seal.php?u=username&seal=64hex\n";
    exit;
}
if (!preg_match('/^[0-9a-f]{64}$/', $seal)) {
    echo "Invalid seal format\n";
    exit;
}

$stmt = $pdo->prepare('UPDATE users SET seal = :s WHERE username = :u');
$stmt->execute([':s' => $seal, ':u' => $username]);

if ($stmt->rowCount() === 0) {
    echo "User not found\n";
    exit;
}

echo "Seal updated for user: {$username}\n";
