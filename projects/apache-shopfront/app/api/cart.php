<?php
/**
 * The basket. POST to add, DELETE to remove, GET to read.
 *
 * Hardened, and the reason the method column in the log is not entirely GET.
 */
require __DIR__ . '/../lib/db.php';
require __DIR__ . '/../lib/session.php';

header('Content-Type: application/json');
start_session();
$basket = $_SESSION['basket'] ?? [];

function basket_count(array $basket): int
{
    $n = 0;
    foreach ($basket as $line) {
        $n += (int) $line['quantity'];
    }
    return $n;
}

$method = $_SERVER['REQUEST_METHOD'];

if ($method === 'POST') {
    $payload = json_decode((string) file_get_contents('php://input'), true) ?: $_POST;
    $id = (int) ($payload['id'] ?? 0);
    $quantity = max(1, (int) ($payload['quantity'] ?? 1));

    $st = db()->prepare('SELECT id, name, price FROM products WHERE id = ?');
    $st->execute([$id]);
    $product = $st->fetch();
    if ($product === false) {
        http_response_code(404);
        echo json_encode(['error' => 'no such product']);
        return;
    }
    if (isset($basket[$id])) {
        $basket[$id]['quantity'] += $quantity;
    } else {
        $basket[$id] = ['id' => $id, 'name' => $product['name'],
                        'price' => (float) $product['price'], 'quantity' => $quantity];
    }
} elseif ($method === 'DELETE') {
    unset($basket[(int) ($_GET['id'] ?? 0)]);
}

$_SESSION['basket'] = $basket;
echo json_encode(['count' => basket_count($basket), 'lines' => array_values($basket)]);
