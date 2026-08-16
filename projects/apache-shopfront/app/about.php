<?php
require __DIR__ . '/lib/db.php';
require __DIR__ . '/lib/render.php';

layout_head('About');
?>
<nav class="crumbs"><a href="/">Home</a> / About</nav>
<h1>About Fettle &amp; Co</h1>
<p>We have sold hardware from the same yard since 1974. Everything we list is
something we would use ourselves, and the people who answer the phone are the
people who pick the stock.</p>
<p>This shop is a deliberately vulnerable test application used to produce
labelled web-server log datasets. It is not a real business, no order placed
here is real, and it is never reachable outside its lab network.</p>
<p><a href="/contact">Get in touch</a>.</p>
<?php
layout_foot();
