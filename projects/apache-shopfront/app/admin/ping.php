<?php
/**
 * Reachability check for a host.
 *
 * PLANTED WEAKNESS 6 -- command injection.
 *
 * The host is interpolated into a shell command with no quoting, so a
 * semicolon appends a second command. Not behind the admin role check either,
 * so any signed-in customer who finds it can reach it.
 * See app/VULNERABILITIES.md.
 */
require __DIR__ . '/../lib/auth.php';
require __DIR__ . '/../lib/render.php';

$host = (string) ($_GET['host'] ?? '');
$output = null;

if ($host !== '') {
    $output = shell_exec('ping -c 1 -W 1 ' . $host . ' 2>&1');
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
