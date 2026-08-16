<?php
/** Hardened: the role check is enforced. */
require __DIR__ . '/../lib/auth.php';
require __DIR__ . '/../lib/render.php';

require_admin();
$rows = db()->query('SELECT id, username, email, role FROM users ORDER BY id')->fetchAll();

layout_head('Users');
?>
<h1>Users</h1>
<table class="basket">
  <tr><th>#</th><th>Username</th><th>Email</th><th>Role</th></tr>
<?php foreach ($rows as $u): ?>
  <tr><td><?= (int) $u['id'] ?></td><td><?= e($u['username']) ?></td>
      <td><?= e($u['email']) ?></td><td><?= e($u['role']) ?></td></tr>
<?php endforeach; ?>
</table>
<?php
layout_foot();
