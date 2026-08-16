<?php
require __DIR__ . '/../lib/auth.php';
require __DIR__ . '/../lib/render.php';

$user = require_login();
layout_head('Your account');
?>
<nav class="crumbs"><a href="/">Home</a> / Account</nav>
<h1>Hello, <?= e($user['username']) ?></h1>
<ul>
  <li><a href="/account/orders">Your orders</a></li>
  <li><a href="/account/addresses">Your addresses</a></li>
  <li><a href="/account/avatar">Change your picture</a></li>
  <li><a href="/logout">Sign out</a></li>
</ul>
<?php
layout_foot();
