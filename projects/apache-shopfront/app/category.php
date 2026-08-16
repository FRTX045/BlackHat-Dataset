<?php
require __DIR__ . '/lib/db.php';
require __DIR__ . '/lib/render.php';

$category = category_by_slug((string) ($_GET['slug'] ?? ''));
if ($category === null) {
    http_response_code(404);
    require __DIR__ . '/404.php';
    return;
}

$products = products_in((int) $category['id']);
layout_head($category['name']);
?>
<nav class="crumbs"><a href="/">Home</a> / <?= e($category['name']) ?></nav>
<h1><?= e($category['name']) ?></h1>
<p class="lede"><?= e($category['blurb']) ?></p>

<section class="grid">
<?php foreach ($products as $p) { product_card($p); } ?>
</section>
<?php
layout_foot();
