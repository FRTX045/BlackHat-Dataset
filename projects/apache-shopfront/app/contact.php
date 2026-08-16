<?php
require __DIR__ . '/lib/db.php';
require __DIR__ . '/lib/render.php';

$sent = false;
$message = (string) ($_POST['message'] ?? '');
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Nothing is delivered anywhere. The point of this endpoint is that it is a
    // POST a person plausibly makes, so the verb distribution in the log is not
    // entirely GET.
    $sent = true;
}

layout_head('Contact');
?>
<nav class="crumbs"><a href="/">Home</a> / Contact</nav>
<h1>Contact us</h1>
<?php if ($sent): ?>
  <p class="notice">Thanks — we will reply to <?= e($message) ?> shortly.</p>
<?php endif; ?>
<form method="post" action="/contact">
  <label for="name">Your name</label>
  <input type="text" name="name" id="name">
  <label for="email">Email</label>
  <input type="email" name="email" id="email">
  <label for="message">Message</label>
  <textarea name="message" id="message" rows="6"></textarea>
  <button type="submit">Send</button>
</form>
<?php
layout_foot();
