<?php
/**
 * A single order.
 *
 * Scoped to the signed-in user here. Task 12 removes that scope deliberately
 * to create the IDOR surface, and VULNERABILITIES.md records the change.
 */
require __DIR__ . '/../lib/auth.php';
require __DIR__ . '/../lib/render.php';

$user = require_login();
$id = (int) ($_GET['id'] ?? 0);

$st = db()->prepare('SELECT * FROM orders WHERE id = ? AND user_id = ?');
$st->execute([$id, $user['id']]);
$order = $st->fetch();

if ($order === false) {
    http_response_code(404);
    require __DIR__ . '/../404.php';
    return;
}

$items = db()->prepare(
    'SELECT oi.*, p.name FROM order_items oi
       JOIN products p ON p.id = oi.product_id
      WHERE oi.order_id = ?');
$items->execute([$id]);

layout_head('Order #' . $id);
?>
<nav class="crumbs"><a href="/">Home</a> / <a href="/account/orders">Orders</a> / #<?= (int) $id ?></nav>
<h1>Order #<?= (int) $id ?></h1>
<p class="lede">Placed <?= e($order['placed_at']) ?> &middot; <?= e($order['status']) ?></p>
<table class="basket">
  <tr><th>Item</th><th>Qty</th><th>Price</th></tr>
<?php foreach ($items->fetchAll() as $line): ?>
  <tr><td><?= e($line['name']) ?></td><td><?= (int) $line['quantity'] ?></td>
      <td>&pound;<?= number_format((float) $line['price'], 2) ?></td></tr>
<?php endforeach; ?>
</table>
<?php
layout_foot();
