<?php
require __DIR__ . '/lib/db.php';
require __DIR__ . '/lib/render.php';

$q = (string) ($_GET['q'] ?? '');

$results = [];
if ($q !== '') {
    $st = db()->prepare(
        'SELECT * FROM products WHERE name LIKE ? OR description LIKE ?
         ORDER BY rating DESC LIMIT 24');
    $st->execute(['%' . $q . '%', '%' . $q . '%']);
    $results = $st->fetchAll();
}

layout_head($q === '' ? 'Search' : "Search: $q");
?>
<nav class="crumbs"><a href="/">Home</a> / Search</nav>
<h1>Search</h1>
<p class="lede"><?= count($results) ?> result(s) for <q><?= e($q) ?></q></p>

<section class="grid">
<?php foreach ($results as $p) { product_card($p); } ?>
</section>
<?php
layout_foot();
