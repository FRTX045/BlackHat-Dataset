<?php
/**
 * Preview a notification template.
 *
 * Hardened for now: {{ }} expressions are looked up in a fixed table rather
 * than evaluated. Task 12 replaces the lookup with evaluation to create the
 * documented SSTI surface.
 *
 * Not behind the admin role check, deliberately.
 */
require __DIR__ . '/../lib/auth.php';
require __DIR__ . '/../lib/render.php';

$tpl = (string) ($_GET['tpl'] ?? 'Hello {{name}}, your order is {{status}}.');

$values = ['name' => 'Customer', 'status' => 'on its way', 'shop' => 'Fettle & Co'];
$rendered = preg_replace_callback(
    '/\{\{\s*([a-z_]+)\s*\}\}/i',
    static fn ($m) => $values[strtolower($m[1])] ?? '',
    $tpl);

layout_head('Template preview');
?>
<h1>Template preview</h1>
<form method="get" action="/admin/template">
  <label for="tpl">Template</label>
  <input type="text" name="tpl" id="tpl" value="<?= e($tpl) ?>">
  <button type="submit">Preview</button>
</form>
<p class="notice"><?= e($rendered) ?></p>
<?php
layout_foot();
