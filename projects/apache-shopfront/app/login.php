<?php
require __DIR__ . '/lib/auth.php';
require __DIR__ . '/lib/render.php';

start_session();
$error = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = (string) ($_POST['username'] ?? '');
    $password = (string) ($_POST['password'] ?? '');

    if (is_locked_out($username)) {
        // 429 rather than 401: a brute-force run in the dataset should be
        // visibly rate-limited in the status column, not merely unsuccessful.
        http_response_code(429);
        $error = 'Too many attempts. Try again later.';
    } elseif (attempt_login($username, $password) !== null) {
        $next = (string) ($_GET['next'] ?? '/account/');
        header('Location: ' . (str_starts_with($next, '/') ? $next : '/account/'));
        http_response_code(302);
        exit;
    } else {
        http_response_code(401);
        $error = 'Those details did not match an account.';
    }
}

layout_head('Sign in');
?>
<h1>Sign in</h1>
<?php if ($error !== null): ?><p class="notice"><?= e($error) ?></p><?php endif; ?>
<form method="post" action="/login">
  <label for="username">Username</label>
  <input type="text" name="username" id="username" autocomplete="username">
  <label for="password">Password</label>
  <input type="password" name="password" id="password" autocomplete="current-password">
  <button type="submit">Sign in</button>
</form>
<p><a href="/register">Create an account</a> · <a href="/password-reset">Forgotten your password?</a></p>
<?php
layout_foot();
