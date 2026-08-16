<?php
require __DIR__ . '/lib/auth.php';
require __DIR__ . '/lib/render.php';

$sent = $_SERVER['REQUEST_METHOD'] === 'POST';

layout_head('Reset your password');
?>
<h1>Reset your password</h1>
<?php if ($sent): ?>
  <p class="notice">If that address is on file we have sent a reset link.</p>
<?php endif; ?>
<form method="post" action="/password-reset">
  <label for="email">Email</label>
  <input type="email" name="email" id="email">
  <button type="submit">Send reset link</button>
</form>
<?php
layout_foot();
