<?php
require __DIR__ . '/lib/db.php';
require __DIR__ . '/lib/render.php';

$item = product((int) ($_GET['id'] ?? 0));
if ($item === null) {
    http_response_code(404);
    require __DIR__ . '/404.php';
    return;
}

$related = array_values(array_filter(
    products_in((int) $item['category_id'], 8),
    static fn ($p) => (int) $p['id'] !== (int) $item['id']));

layout_head($item['name']);
?>
<nav class="crumbs">
  <a href="/">Home</a> /
  <a href="/c/<?= e($item['category_slug']) ?>"><?= e($item['category_name']) ?></a> /
  <?= e($item['name']) ?>
</nav>

<article class="product">
  <img src="/assets/img/p/<?= (int) $item['id'] ?>.jpg" alt="<?= e($item['name']) ?>" width="640" height="420">
  <div class="detail">
    <h1><?= e($item['name']) ?></h1>
    <p class="sku">SKU <?= e($item['sku']) ?></p>
    <p class="price">£<?= number_format((float) $item['price'], 2) ?></p>
    <p class="rating"><?= e((string) $item['rating']) ?> out of 5</p>
    <p class="stock" data-product="<?= (int) $item['id'] ?>"><?= (int) $item['stock'] ?> in stock</p>
    <p><?= e($item['description']) ?></p>
    <button class="add" data-product="<?= (int) $item['id'] ?>">Add to basket</button>
  </div>
</article>

<section class="grid related">
  <h2>Others in <?= e($item['category_name']) ?></h2>
<?php foreach (array_slice($related, 0, 6) as $p) { product_card($p); } ?>
</section>
<?php
layout_foot();
