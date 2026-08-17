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
    echo json_encode(['error' => 'no such product',
                      'code' => 'stock.not_found', 'id' => $id]);
    return;
}

/*
 * A realistic payload, not `{"id":3,"stock":42}`.
 *
 * The previous version answered in about twenty bytes, and since api_call is
 * roughly 5% of the log that put a visible cluster of twenty-byte responses in
 * `%b` that no real endpoint produces. A stock check on a real storefront
 * answers with per-warehouse availability, a delivery estimate and the
 * fulfilment options the front end needs to render the buy box without a
 * second round trip.
 *
 * Derived from the product id so it is deterministic and consistent between
 * requests for the same product, which is what a cache-correctness experiment
 * on this data would need.
 */
$stock = (int) $row['stock'];
$warehouses = [];
foreach (['ncl' => 'Newcastle', 'brm' => 'Birmingham',
          'gla' => 'Glasgow', 'brs' => 'Bristol'] as $code => $name) {
    $here = (int) floor($stock * ((crc32($code . $id) % 40) / 100.0));
    $warehouses[] = [
        'code' => $code,
        'name' => $name,
        'available' => $here,
        'reserved' => (int) floor($here * 0.12),
        'collection' => $here > 0,
        'restock_days' => $here > 0 ? 0 : 3 + ($id % 12),
    ];
}

echo json_encode([
    'id' => (int) $row['id'],
    'stock' => $stock,
    'status' => $stock > 8 ? 'in_stock' : ($stock > 0 ? 'low_stock' : 'out_of_stock'),
    'warehouses' => $warehouses,
    'fulfilment' => [
        'same_day_dispatch' => $stock > 0,
        'cutoff' => '16:00',
        'options' => [
            ['code' => 'standard', 'name' => 'Standard delivery',
             'price' => 495, 'free_over' => 5000,
             'min_days' => 1, 'max_days' => 3],
            ['code' => 'express', 'name' => 'Next working day',
             'price' => 995, 'free_over' => null,
             'min_days' => 1, 'max_days' => 1],
            ['code' => 'collect', 'name' => 'Collect from branch',
             'price' => 0, 'free_over' => null,
             'min_days' => 0, 'max_days' => 1],
        ],
    ],
    'returns' => ['window_days' => 30, 'condition' => 'unused',
                  'collection_available' => true],
    'updated_at' => gmdate('c', 1772582400 + ($id * 137)),
]);
