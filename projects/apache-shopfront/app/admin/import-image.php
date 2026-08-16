<?php
/**
 * Fetch a product image from a URL, server-side.
 *
 * This is the SSRF surface, and it is deliberate: the URL is taken from the
 * caller and fetched by the server with no restriction on scheme or host. It
 * is also NOT behind the admin role check, so it is reachable by any signed-in
 * customer who finds it. Both facts are recorded in VULNERABILITIES.md.
 *
 * Nothing here can reach outside the lab: the container has no route off the
 * three lab networks, so an attempt at a cloud metadata address or an external
 * host fails at the network layer. What lands in the dataset is the attempt,
 * which is the part a log analyst has to learn to recognise.
 */
require __DIR__ . '/../lib/auth.php';
require __DIR__ . '/../lib/render.php';

$url = (string) ($_GET['url'] ?? '');
$bytes = null;
$error = null;

if ($url !== '') {
    $context = stream_context_create([
        'http' => ['timeout' => 4, 'ignore_errors' => true,
                   'user_agent' => 'FettleImporter/1.0'],
    ]);
    $body = @file_get_contents($url, false, $context);
    if ($body === false) {
        // A 504 rather than a 500: a fetch that could not be completed is a
        // gateway problem, and the distinction is visible in the access log.
        http_response_code(504);
        $error = 'That URL could not be fetched.';
    } else {
        $bytes = strlen($body);
    }
}

layout_head('Import an image');
?>
<h1>Import a product image</h1>
<?php if ($bytes !== null): ?>
  <p class="notice">Fetched <?= (int) $bytes ?> bytes from <?= e($url) ?>.</p>
<?php endif; ?>
<?php if ($error !== null): ?><p class="notice"><?= e($error) ?></p><?php endif; ?>
<form method="get" action="/admin/import-image">
  <label for="url">Image URL</label>
  <input type="text" name="url" id="url" value="<?= e($url) ?>">
  <button type="submit">Fetch</button>
</form>
<?php
layout_foot();
