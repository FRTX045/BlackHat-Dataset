<?php
/**
 * A real sitemap, generated from the catalogue.
 *
 * Crawler personas fetch this and then walk it, so the URLs a well-behaved bot
 * visits in the log are exactly the URLs the site actually publishes -- rather
 * than a list the traffic driver was handed separately.
 */
require __DIR__ . '/lib/db.php';

header('Content-Type: application/xml; charset=utf-8');
echo '<?xml version="1.0" encoding="UTF-8"?>' . "\n";
?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>http://shop.test/</loc><changefreq>daily</changefreq></url>
  <url><loc>http://shop.test/about</loc><changefreq>monthly</changefreq></url>
  <url><loc>http://shop.test/contact</loc><changefreq>monthly</changefreq></url>
<?php foreach (categories() as $c): ?>
  <url><loc>http://shop.test/c/<?= htmlspecialchars($c['slug']) ?></loc><changefreq>weekly</changefreq></url>
<?php endforeach; ?>
<?php foreach (all_products() as $p): ?>
  <url><loc>http://shop.test/p/<?= (int) $p['id'] ?></loc><changefreq>weekly</changefreq></url>
<?php endforeach; ?>
</urlset>
