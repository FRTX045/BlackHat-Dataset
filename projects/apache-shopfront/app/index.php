<?php
require __DIR__ . '/lib/db.php';
require __DIR__ . '/lib/render.php';

$featured = featured(12);
layout_head('Tools and hardware', [
    'page' => 'home',
    'canonical' => 'http://shop.test/',
    'description' => 'Hand tools, power tools, fixings, garden kit and '
        . 'workwear, chosen by people who use them. Everything in stock ships '
        . 'the same day.',
]);
product_list_ld($featured, 'Featured products');
?>
<h1>Fettle &amp; Co</h1>
<p class="lede">Hardware chosen by people who use it. Everything in stock ships the same day.</p>

<section class="grid">
<?php foreach ($featured as $i => $p) { product_card($p, $i); } ?>
</section>

<section class="browse">
  <h2>Browse by department</h2>
  <ul>
<?php foreach (categories() as $c): ?>
    <li><a href="/c/<?= e($c['slug']) ?>"><?= e($c['name']) ?></a> — <?= e($c['blurb']) ?></li>
<?php endforeach; ?>
  </ul>
</section>
<?php
layout_foot();
