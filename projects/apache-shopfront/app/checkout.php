<?php
/**
 * Checkout.
 *
 * Contains a real bug, kept on purpose: the basket total is computed from the
 * session basket without checking it exists, so arriving here without one is
 * an uncaught TypeError and a genuine 500 -- with a matching entry in the
 * error log beside the access log line.
 *
 * This is how the dataset gets 500s. A page that prints "500" and returns 200,
 * or one that calls http_response_code(500) deliberately, would give the
 * access log the right status with none of the surrounding evidence, and
 * anyone correlating the two logs would find nothing on the other side.
 */
require __DIR__ . '/lib/db.php';
require __DIR__ . '/lib/render.php';
require __DIR__ . '/lib/session.php';

start_session();

function basket_total(array $lines): float
{
    $total = 0.0;
    foreach ($lines as $line) {
        $total += $line['price'] * $line['quantity'];
    }
    return $total;
}

$basket = $_SESSION['basket'] ?? null;
$total = basket_total($basket);   // TypeError when the basket is null.

layout_head('Checkout');
?>
<h1>Checkout</h1>
<p class="lede">Basket total £<?= number_format($total, 2) ?></p>
<form method="post" action="/checkout">
  <button type="submit">Place order</button>
</form>
<?php
layout_foot();
