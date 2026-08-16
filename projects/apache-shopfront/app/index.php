<?php
require __DIR__ . '/lib/db.php';
require __DIR__ . '/lib/render.php';

$featured = featured(12);
layout_head('Tools and hardware');
?>
<h1>Fettle &amp; Co</h1>
<p class="lede">Hardware chosen by people who use it. Everything in stock ships the same day.</p>

<section class="grid">
<?php foreach ($featured as $p) { product_card($p); } ?>
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
