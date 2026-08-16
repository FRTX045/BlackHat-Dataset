<?php
/**
 * Avatar upload.
 *
 * The check here is on the MIME type the browser declares and the extension,
 * which is exactly the shape of check real applications get wrong. Task 12
 * widens it into the documented upload bypass; for now it accepts an image and
 * rejects anything else.
 *
 * The upload directory executes PHP -- that part is already deliberate, and
 * configured in the vhost.
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
            $name = sprintf('u%d-%s.%s', $user['id'],
                            substr(sha1($file['name'] . $user['id']), 0, 10), $extension);
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
