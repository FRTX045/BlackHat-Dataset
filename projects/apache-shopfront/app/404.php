<?php
/**
 * Served by ErrorDocument, which preserves the original 404 status, and also
 * required directly by pages that resolve nothing.
 *
 * Guarded: a 404 raised because the catalogue is missing must not turn into a
 * 500 from this page trying to render a category menu.
 */
require_once __DIR__ . '/lib/db.php';
require_once __DIR__ . '/lib/render.php';

try {
    layout_head('Not found');
    $full = true;
} catch (Throwable $e) {
    $full = false;
    echo "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
       . "<title>Not found</title></head><body>";
}
?>
<h1>Not found</h1>
<p class="lede">We could not find that page. It may have been discontinued.</p>
<p><a href="/">Back to the shop</a> or <a href="/contact">tell us what you were after</a>.</p>
<?php
if ($full) {
    layout_foot();
} else {
    echo '</body></html>';
}
