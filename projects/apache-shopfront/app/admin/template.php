<?php
/**
 * Preview a notification template.
 *
 * PLANTED WEAKNESS 7 -- server-side template injection.
 *
 * A {{ }} expression is evaluated rather than looked up, so it is arbitrary
 * PHP. Not behind the admin role check either.
 * See app/VULNERABILITIES.md.
 */
require __DIR__ . '/../lib/auth.php';
require __DIR__ . '/../lib/render.php';

$tpl = (string) ($_GET['tpl'] ?? 'Hello {{name}}, your order is {{status}}.');

$name = 'Customer';
$status = 'on its way';
$shop = 'Fettle & Co';

$rendered = preg_replace_callback(
    '/\{\{(.+?)\}\}/',
    static function (array $m) {
        try {
            // The bug: the expression is evaluated, not resolved.
            return (string) @eval('return ' . $m[1] . ';');
        } catch (Throwable $e) {
            return '';
        }
    },
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
