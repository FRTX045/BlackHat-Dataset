<?php
require __DIR__ . '/lib/auth.php';
require __DIR__ . '/lib/render.php';

$done = false;
$error = null;
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim((string) ($_POST['username'] ?? ''));
    $email = trim((string) ($_POST['email'] ?? ''));
    $password = (string) ($_POST['password'] ?? '');
    if ($username === '' || $password === '') {
        $error = 'Pick a username and a password.';
    } elseif (user_by_username($username) !== null) {
        $error = 'That username is taken.';
    } else {
        $st = db()->prepare(
            'INSERT INTO users (username, email, password_hash, role)
             VALUES (?, ?, ?, ?)');
        $st->execute([$username, $email,
                      password_hash($password, PASSWORD_DEFAULT), 'customer']);
        $done = true;
    }
}

layout_head('Create an account');
?>
<h1>Create an account</h1>
<?php if ($done): ?><p class="notice">Account created. <a href="/login">Sign in</a>.</p><?php endif; ?>
<?php if ($error !== null): ?><p class="notice"><?= e($error) ?></p><?php endif; ?>
<form method="post" action="/register">
  <label for="username">Username</label>
  <input type="text" name="username" id="username">
  <label for="email">Email</label>
  <input type="email" name="email" id="email">
  <label for="password">Password</label>
  <input type="password" name="password" id="password">
  <button type="submit">Create account</button>
</form>
<?php
layout_foot();
