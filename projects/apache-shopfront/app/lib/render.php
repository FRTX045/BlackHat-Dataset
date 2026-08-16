<?php
/**
 * Page layout.
 *
 * The head deliberately pulls a realistic number of subresources. One page
 * view in a real access log is a burst -- the HTML, then a cascade of CSS,
 * JS, fonts and images in the same second. A log where every line is an HTML
 * page is the single most obvious sign of a generated dataset, so the shape
 * of this function is a property the data depends on.
 */

function e(?string $s): string
{
    return htmlspecialchars((string) $s, ENT_QUOTES, 'UTF-8');
}

function layout_head(string $title): void
{
    ?><!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title><?= e($title) ?> — Fettle &amp; Co</title>
<link rel="stylesheet" href="/assets/css/site.css">
<link rel="stylesheet" href="/assets/css/layout.css">
<link rel="stylesheet" href="/assets/css/components.css">
<link rel="preload" as="font" type="font/woff2" href="/assets/fonts/inter-400.woff2" crossorigin>
<link rel="preload" as="font" type="font/woff2" href="/assets/fonts/inter-600.woff2" crossorigin>
<link rel="icon" href="/favicon.ico">
<link rel="apple-touch-icon" href="/apple-touch-icon.png">
<script src="/assets/js/app.js" defer></script>
<script src="/assets/js/cart.js" defer></script>
<script src="/assets/js/autocomplete.js" defer></script>
</head>
<body>
<header class="masthead">
  <a class="brand" href="/"><img src="/assets/img/logo.png" alt="Fettle &amp; Co" width="132" height="32"></a>
  <form class="search" action="/search" method="get">
    <input type="search" name="q" id="q" placeholder="Search the catalogue" autocomplete="off">
    <button type="submit">Search</button>
  </form>
  <nav class="account">
    <a href="/account/">Account</a>
    <a href="/cart">Cart <span id="cart-count">0</span></a>
  </nav>
</header>
<nav class="categories">
<?php foreach (categories() as $c): ?>
  <a href="/c/<?= e($c['slug']) ?>"><?= e($c['name']) ?></a>
<?php endforeach; ?>
</nav>
<main>
<?php
}

function layout_foot(): void
{
    ?>
</main>
<footer>
  <a href="/about">About</a>
  <a href="/contact">Contact</a>
  <a href="/robots.txt">robots.txt</a>
  <p>&copy; Fettle &amp; Co. A deliberately vulnerable test application.</p>
</footer>
</body>
</html>
<?php
}

/** A product card, including its image -- this is what makes the cascade. */
function product_card(array $p): void
{
    ?>
<article class="card">
  <a href="/p/<?= (int) $p['id'] ?>">
    <img src="/assets/img/p/<?= (int) $p['id'] ?>.jpg" alt="<?= e($p['name']) ?>" width="240" height="180" loading="lazy">
    <h3><?= e($p['name']) ?></h3>
  </a>
  <p class="price">£<?= number_format((float) $p['price'], 2) ?></p>
  <button class="add" data-product="<?= (int) $p['id'] ?>">Add to basket</button>
</article>
<?php
}
