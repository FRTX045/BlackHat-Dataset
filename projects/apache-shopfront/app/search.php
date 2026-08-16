<?php
require __DIR__ . '/lib/db.php';
require __DIR__ . '/lib/render.php';

$q = (string) ($_GET['q'] ?? '');

$results = [];
$failed = false;
if ($q !== '') {
    // PLANTED WEAKNESS 1 -- SQL injection.
    //
    // The search term is concatenated straight into the statement. Everything
    // else in this application uses prepared statements; this endpoint is the
    // documented exception. See app/VULNERABILITIES.md.
    $sql = "SELECT * FROM products
             WHERE name LIKE '%$q%' OR description LIKE '%$q%'
             ORDER BY rating DESC LIMIT 24";
    try {
        $results = db()->query($sql)->fetchAll();
    } catch (PDOException $e) {
        // A broken payload produces an empty result page, not a 500. Real
        // injectable endpoints usually swallow the error, and a probe that
        // reliably returned 500 would be trivially separable in the log.
        $failed = true;
    }
}

layout_head($q === '' ? 'Search' : 'Search results');
?>
<nav class="crumbs"><a href="/">Home</a> / Search</nav>
<h1>Search</h1>
<?php
// PLANTED WEAKNESS 8 -- reflected XSS. The term is echoed unescaped here and
// nowhere else. Barely visible in an access log; documented as such.
?>
<p class="lede"><?= count($results) ?> result(s) for <q><?= $q ?></q></p>
<?php if ($failed): ?><p class="notice">That search could not be run.</p><?php endif; ?>

<section class="grid">
<?php foreach ($results as $p) { product_card($p); } ?>
</section>
<?php
layout_foot();
