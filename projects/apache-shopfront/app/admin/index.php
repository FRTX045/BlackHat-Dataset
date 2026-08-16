<?php
/**
 * The admin landing page requires a session but NOT the admin role.
 *
 * Deliberate: an ordinary customer who guesses the URL sees the menu. It is
 * the forced-browsing surface, and it is what makes the 403s on /admin/users
 * and /admin/orders meaningful by contrast. Recorded in VULNERABILITIES.md.
 */
require __DIR__ . '/../lib/auth.php';
require __DIR__ . '/../lib/render.php';

$user = require_login();
layout_head('Administration');
?>
<h1>Administration</h1>
<p class="lede">Signed in as <?= e($user['username']) ?> (<?= e($user['role']) ?>).</p>
<ul>
  <li><a href="/admin/users">Users</a></li>
  <li><a href="/admin/orders">All orders</a></li>
  <li><a href="/admin/import-image?url=">Import a product image</a></li>
  <li><a href="/admin/ping?host=127.0.0.1">Check a host</a></li>
  <li><a href="/admin/template?tpl=Hello">Preview a template</a></li>
</ul>
<?php
layout_foot();
