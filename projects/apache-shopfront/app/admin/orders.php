<?php
/** Hardened: the role check is enforced. */
require __DIR__ . '/../lib/auth.php';
require __DIR__ . '/../lib/render.php';

require_admin();
$rows = db()->query(
    'SELECT o.*, u.username FROM orders o JOIN users u ON u.id = o.user_id
      ORDER BY o.id')->fetchAll();

layout_head('All orders');
?>
<h1>All orders</h1>
<table class="basket">
  <tr><th>#</th><th>Customer</th><th>Placed</th><th>Status</th><th>Total</th></tr>
<?php foreach ($rows as $o): ?>
  <tr><td><?= (int) $o['id'] ?></td><td><?= e($o['username']) ?></td>
      <td><?= e($o['placed_at']) ?></td><td><?= e($o['status']) ?></td>
      <td>&pound;<?= number_format((float) $o['total'], 2) ?></td></tr>
<?php endforeach; ?>
</table>
<?php
layout_foot();
