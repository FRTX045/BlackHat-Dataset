<?php
/** Hardened: prepared statement. Called by app.js on every product view. */
require __DIR__ . '/../lib/db.php';

header('Content-Type: application/json');
$id = (int) ($_GET['id'] ?? 0);
$st = db()->prepare('SELECT id, stock FROM products WHERE id = ?');
$st->execute([$id]);
$row = $st->fetch();

if ($row === false) {
    http_response_code(404);
    echo json_encode(['error' => 'no such product']);
    return;
}
echo json_encode(['id' => (int) $row['id'], 'stock' => (int) $row['stock']]);
