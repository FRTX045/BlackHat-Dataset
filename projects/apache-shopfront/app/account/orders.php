<?php
require __DIR__ . '/../lib/auth.php';
require __DIR__ . '/../lib/render.php';

$user = require_login();
$st = db()->prepare(
    'SELECT * FROM orders WHERE user_id = ? ORDER BY id');
$st->execute([$user['id']]);
$orders = $st->fetchAll();

layout_head('Your orders');
?>
<nav class="crumbs"><a href="/">Home</a> / <a href="/account/">Account</a> / Orders</nav>
<h1>Your orders</h1>
<table class="basket">
  <tr><th>Order</th><th>Placed</th><th>Status</th><th>Total</th></tr>
<?php foreach ($orders as $o): ?>
  <tr>
    <td><a href="/account/orders/<?= (int) $o['id'] ?>">#<?= (int) $o['id'] ?></a></td>
    <td><?= e($o['placed_at']) ?></td>
    <td><?= e($o['status']) ?></td>
    <td>&pound;<?= number_format((float) $o['total'], 2) ?></td>
  </tr>
<?php endforeach; ?>
</table>
<?php
layout_foot();
