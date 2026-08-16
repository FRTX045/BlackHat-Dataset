<?php
/**
 * Reachability check for a host.
 *
 * Hardened for now with escapeshellarg. Task 12 removes that to create the
 * documented command-injection surface; the change and what a successful
 * exploit looks like in the log are recorded in VULNERABILITIES.md.
 *
 * Not behind the admin role check, deliberately.
 */
require __DIR__ . '/../lib/auth.php';
require __DIR__ . '/../lib/render.php';

$host = (string) ($_GET['host'] ?? '');
$output = null;

if ($host !== '') {
    $output = shell_exec('ping -c 1 -W 1 ' . escapeshellarg($host) . ' 2>&1');
}

layout_head('Check a host');
?>
<h1>Check a host</h1>
<form method="get" action="/admin/ping">
  <label for="host">Host</label>
  <input type="text" name="host" id="host" value="<?= e($host) ?>">
  <button type="submit">Check</button>
</form>
<?php if ($output !== null): ?><pre><?= e($output) ?></pre><?php endif; ?>
<?php
layout_foot();
