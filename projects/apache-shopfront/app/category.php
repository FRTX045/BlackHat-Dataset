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
layout_head($category['name'], [
    'page' => 'category',
    'canonical' => 'http://shop.test/c/' . $category['slug'],
    'description' => $category['blurb'],
    'crumbs' => ['/c/' . $category['slug'] => $category['name']],
]);
product_list_ld($products, $category['name']);
?>
<div class="banner dept-<?= e($category['slug']) ?>">
  <h1><?= e($category['name']) ?></h1>
  <p class="lede"><?= e($category['blurb']) ?></p>
  <p class="meta"><?= count($products) ?> products &middot; all in stock ship the same day</p>
</div>

<div class="toolbar">
  <form class="filters" action="/c/<?= e($category['slug']) ?>" method="get">
    <div class="field">
      <label for="sort">Sort by</label>
      <select id="sort" name="sort">
        <option value="relevance">Relevance</option>
        <option value="price-asc">Price, low to high</option>
        <option value="price-desc">Price, high to low</option>
        <option value="rating">Customer rating</option>
        <option value="newest">Newest first</option>
      </select>
    </div>
    <div class="field">
      <label for="min">Price from</label>
      <input type="number" id="min" name="min" min="0" step="1" placeholder="0">
    </div>
    <div class="field">
      <label for="max">Price to</label>
      <input type="number" id="max" name="max" min="0" step="1" placeholder="500">
    </div>
    <fieldset class="field">
      <legend>Availability</legend>
      <label><input type="checkbox" name="instock" value="1"> In stock only</label>
      <label><input type="checkbox" name="trade" value="1"> Trade priced</label>
    </fieldset>
    <button type="submit" class="btn-secondary btn-sm">Apply</button>
  </form>
</div>

<section class="grid">
<?php foreach ($products as $i => $p) { product_card($p, $i); } ?>
</section>

<nav class="pagination" aria-label="Pagination">
<?php foreach (range(1, 4) as $page): ?>
  <a class="btn-ghost btn-sm<?= $page === 1 ? ' is-active' : '' ?>" href="/c/<?= e($category['slug']) ?>?page=<?= $page ?>"><?= $page ?></a>
<?php endforeach; ?>
</nav>

<section class="prose">
  <h2>About <?= e($category['name']) ?></h2>
  <p><?= e($category['blurb']) ?> Everything listed here is held in the
  warehouse and dispatched the same working day when ordered before 4pm.</p>
  <p>Trade customers get tiered pricing across the whole department and 30-day
  terms. Bulk quantities not listed here can usually be sourced within a week.</p>
</section>
<?php
layout_foot();
