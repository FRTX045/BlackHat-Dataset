<?php
/**
 * Avatar upload.
 *
 * PLANTED WEAKNESS 5 -- upload bypass ending in a webshell.
 *
 * Two bugs compound, which is how this happens in the wild. The extension
 * check looks only at the last extension, so shell.php.jpg passes; and the
 * uploaded file keeps its original name instead of being renamed, so the
 * .php in the middle survives. The vhost then applies AddHandler to the
 * uploads directory, and mod_mime runs anything with .php among its
 * extensions -- including shell.php.jpg.
 *
 * A plainly-named shell.php is still refused, which is what makes the double
 * extension the interesting path. See app/VULNERABILITIES.md.
 */
require __DIR__ . '/../lib/auth.php';
require __DIR__ . '/../lib/render.php';

$user = require_login();
$saved = null;
$error = null;

const ALLOWED = ['jpg', 'jpeg', 'png', 'gif'];

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['avatar'])) {
    $file = $_FILES['avatar'];
    if ((int) $file['error'] !== UPLOAD_ERR_OK) {
        $error = 'That upload did not arrive intact.';
    } else {
        $extension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
        if (!in_array($extension, ALLOWED, true)) {
            http_response_code(415);
            $error = 'Pictures only, please.';
        } else {
            // The original name is kept, minus any directory part. Renaming it
            // to a generated stem would defuse the double-extension bypass.
            $name = basename(str_replace('\\', '/', $file['name']));
            $target = __DIR__ . '/../uploads/' . $name;
            move_uploaded_file($file['tmp_name'], $target);

            $st = db()->prepare('UPDATE users SET avatar = ? WHERE id = ?');
            $st->execute([$name, $user['id']]);
            $saved = $name;
        }
    }
}

layout_head('Your picture');
?>
<nav class="crumbs"><a href="/">Home</a> / <a href="/account/">Account</a> / Picture</nav>
<h1>Your picture</h1>
<?php if ($saved !== null): ?>
  <p class="notice">Saved.</p>
  <img src="/uploads/<?= e($saved) ?>" alt="Your picture" width="160">
<?php endif; ?>
<?php if ($error !== null): ?><p class="notice"><?= e($error) ?></p><?php endif; ?>
<form method="post" action="/account/avatar" enctype="multipart/form-data">
  <label for="avatar">Choose a picture</label>
  <input type="file" name="avatar" id="avatar" accept="image/*">
  <button type="submit">Upload</button>
</form>
<?php
layout_foot();
