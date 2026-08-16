<?php
require __DIR__ . '/lib/db.php';
require __DIR__ . '/lib/render.php';
require __DIR__ . '/lib/session.php';

start_session();
$basket = $_SESSION['basket'] ?? [];

layout_head('Your basket');
?>
<nav class="crumbs"><a href="/">Home</a> / Basket</nav>
<h1>Your basket</h1>
<?php if (!$basket): ?>
  <p class="lede">Your basket is empty. <a href="/">Keep looking</a>.</p>
<?php else: ?>
  <table class="basket">
    <tr><th>Item</th><th>Qty</th><th>Price</th></tr>
<?php foreach ($basket as $line): ?>
    <tr>
      <td><a href="/p/<?= (int) $line['id'] ?>"><?= e($line['name']) ?></a></td>
      <td><?= (int) $line['quantity'] ?></td>
      <td>£<?= number_format((float) $line['price'], 2) ?></td>
    </tr>
<?php endforeach; ?>
  </table>
  <p><a class="button" href="/checkout">Checkout</a></p>
<?php endif; ?>
<?php
layout_foot();
