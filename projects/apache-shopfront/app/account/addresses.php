<?php
/** Scoped by session user, and stays that way: a hardened counterpart to the
 *  order lookup, so forced-browsing attempts here fail. */
require __DIR__ . '/../lib/auth.php';
require __DIR__ . '/../lib/render.php';

$user = require_login();
$st = db()->prepare('SELECT * FROM addresses WHERE user_id = ? ORDER BY id');
$st->execute([$user['id']]);

layout_head('Your addresses');
?>
<nav class="crumbs"><a href="/">Home</a> / <a href="/account/">Account</a> / Addresses</nav>
<h1>Your addresses</h1>
<?php foreach ($st->fetchAll() as $a): ?>
  <address><strong><?= e($a['label']) ?></strong><br>
    <?= e($a['line1']) ?><br><?= e($a['city']) ?><br><?= e($a['postcode']) ?></address>
<?php endforeach; ?>
<?php
layout_foot();
