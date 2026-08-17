<?php
/**
 * Page layout.
 *
 * Two properties of the access log depend on the shape of this file.
 *
 * **The cascade.** The head deliberately pulls a realistic number of
 * subresources. One page view in a real access log is a burst -- the HTML,
 * then CSS, JS, fonts and images in the same second. A log where every line
 * is an HTML page is the single most obvious sign of a generated dataset.
 *
 * **The byte count.** The layout used to emit about 1.4 KB on the wire, and
 * Apache recorded that honestly. A real e-commerce document is 5-25 KB
 * gzipped, so `%b` -- the column real analysis uses for exfiltration volume,
 * response-size anomalies and cache work -- was off by an order of magnitude
 * and every aggregate check passed anyway. Found by reading twenty-five lines
 * of a shipped log by eye.
 *
 * So the markup here is what a shop actually emits: meta and social tags,
 * canonical links, JSON-LD, a department menu, breadcrumbs, product cards
 * carrying price, rating, stock and SKU, a multi-column footer, a cookie bar
 * and a newsletter block. None of it is padding; all of it is markup a real
 * storefront has, and a browser renders it.
 */

function e(?string $s): string
{
    return htmlspecialchars((string) $s, ENT_QUOTES, 'UTF-8');
}

/** Structured data, which every commerce page carries and crawlers read. */
function json_ld(array $blocks): void
{
    foreach ($blocks as $block) {
        echo '<script type="application/ld+json">',
             json_encode($block, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT),
             "</script>\n";
    }
}

function layout_head(string $title, array $options = []): void
{
    $page = $options['page'] ?? 'home';
    $description = $options['description']
        ?? 'Hand tools, power tools, fixings and workwear from Fettle & Co. '
           . 'Everything in stock ships the same day, with free returns for '
           . 'thirty days and trade accounts available.';
    $canonical = $options['canonical'] ?? '/';
    $crumbs = $options['crumbs'] ?? [];
    ?><!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="description" content="<?= e($description) ?>">
<meta name="robots" content="index,follow,max-image-preview:large">
<meta name="theme-color" content="#1a2a3a">
<meta name="format-detection" content="telephone=no">
<meta property="og:site_name" content="Fettle &amp; Co">
<meta property="og:type" content="website">
<meta property="og:title" content="<?= e($title) ?>">
<meta property="og:description" content="<?= e($description) ?>">
<meta property="og:url" content="<?= e($canonical) ?>">
<meta property="og:image" content="/assets/img/logo.png">
<meta property="og:locale" content="en_GB">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="<?= e($title) ?>">
<meta name="twitter:description" content="<?= e($description) ?>">
<meta name="twitter:image" content="/assets/img/logo.png">
<link rel="canonical" href="<?= e($canonical) ?>">
<title><?= e($title) ?> — Fettle &amp; Co</title>
<link rel="stylesheet" href="/assets/css/site.css">
<link rel="stylesheet" href="/assets/css/layout.css">
<link rel="stylesheet" href="/assets/css/components.css">
<link rel="preload" as="font" type="font/woff2" href="/assets/fonts/inter-400.woff2" crossorigin>
<link rel="preload" as="font" type="font/woff2" href="/assets/fonts/inter-600.woff2" crossorigin>
<link rel="icon" href="/favicon.ico">
<link rel="apple-touch-icon" href="/apple-touch-icon.png">
<link rel="search" type="application/opensearchdescription+xml" title="Fettle &amp; Co" href="/opensearch.xml">
<link rel="sitemap" type="application/xml" href="/sitemap.xml">
<script src="/assets/js/app.js" defer></script>
<script src="/assets/js/cart.js" defer></script>
<script src="/assets/js/autocomplete.js" defer></script>
<?php
json_ld([
    [
        '@context' => 'https://schema.org',
        '@type' => 'Organization',
        'name' => 'Fettle & Co',
        'url' => 'http://shop.test/',
        'logo' => 'http://shop.test/assets/img/logo.png',
        'contactPoint' => [
            '@type' => 'ContactPoint',
            'contactType' => 'customer support',
            'availableLanguage' => ['en-GB'],
            'areaServed' => 'GB',
        ],
    ],
    [
        '@context' => 'https://schema.org',
        '@type' => 'WebSite',
        'name' => 'Fettle & Co',
        'url' => 'http://shop.test/',
        'potentialAction' => [
            '@type' => 'SearchAction',
            'target' => 'http://shop.test/search?q={search_term_string}',
            'query-input' => 'required name=search_term_string',
        ],
    ],
]);
?>
</head>
<body class="page-<?= e($page) ?>">
<a class="skip" href="#main">Skip to content</a>
<header class="masthead">
  <a class="brand" href="/"><img src="/assets/img/logo.png" alt="Fettle &amp; Co" width="132" height="32"></a>
  <form class="search" action="/search" method="get" role="search">
    <label class="visually-hidden" for="q">Search the catalogue</label>
    <input type="search" name="q" id="q" placeholder="Search the catalogue" autocomplete="off" autocapitalize="none" spellcheck="false">
    <button type="submit" class="btn-primary btn-md">Search</button>
  </form>
  <nav class="account" aria-label="Account">
    <a href="/account/">Account</a>
    <a href="/account/orders">Orders</a>
    <a href="/cart" data-cart-link>Cart <span id="cart-count">0</span></a>
  </nav>
</header>
<nav class="categories" aria-label="Departments">
<?php foreach (categories() as $c): ?>
  <a class="chip dept-<?= e($c['slug']) ?>" href="/c/<?= e($c['slug']) ?>" data-department="<?= e($c['slug']) ?>"><?= e($c['name']) ?></a>
<?php endforeach; ?>
</nav>
<?php if ($crumbs): ?>
<nav class="breadcrumbs" aria-label="Breadcrumb">
  <ol>
    <li><a href="/">Home</a></li>
<?php foreach ($crumbs as $href => $label): ?>
    <li><a href="<?= e((string) $href) ?>"><?= e($label) ?></a></li>
<?php endforeach; ?>
  </ol>
</nav>
<?php
    json_ld([[
        '@context' => 'https://schema.org',
        '@type' => 'BreadcrumbList',
        'itemListElement' => array_map(
            static fn ($i, $href, $label) => [
                '@type' => 'ListItem',
                'position' => $i + 1,
                'name' => $label,
                'item' => 'http://shop.test' . $href,
            ],
            range(0, count($crumbs) - 1),
            array_keys($crumbs),
            array_values($crumbs)
        ),
    ]]);
endif; ?>
<main id="main">
<?php
}

function layout_foot(): void
{
    $columns = [
        'Shop' => ['/c/hand-tools' => 'Hand tools',
                   '/c/power-tools' => 'Power tools',
                   '/c/fixings' => 'Fixings',
                   '/c/garden' => 'Garden',
                   '/c/workwear' => 'Workwear'],
        'Help' => ['/about' => 'About us', '/contact' => 'Contact',
                   '/about#delivery' => 'Delivery', '/about#returns' => 'Returns',
                   '/about#warranty' => 'Warranty'],
        'Account' => ['/account/' => 'Your account',
                      '/account/orders' => 'Your orders',
                      '/account/addresses' => 'Address book',
                      '/login' => 'Sign in', '/register' => 'Create an account'],
        'More' => ['/robots.txt' => 'robots.txt', '/sitemap.xml' => 'Sitemap',
                   '/about#terms' => 'Terms', '/about#privacy' => 'Privacy',
                   '/about#cookies' => 'Cookies'],
    ];
    ?>
</main>
<section class="newsletter">
  <div>
    <h2>Trade prices, once a month</h2>
    <p>Stock alerts and clearance, no more than one email a month.</p>
  </div>
  <form action="/contact" method="post" class="newsletter-form">
    <label class="visually-hidden" for="nl">Email address</label>
    <input type="email" id="nl" name="email" placeholder="you@example.com" required>
    <button type="submit" class="btn-primary btn-md">Sign up</button>
  </form>
</section>
<footer class="footer">
<?php foreach ($columns as $heading => $links): ?>
  <nav aria-label="<?= e($heading) ?>">
    <h3><?= e($heading) ?></h3>
    <ul>
<?php foreach ($links as $href => $label): ?>
      <li><a href="<?= e((string) $href) ?>"><?= e($label) ?></a></li>
<?php endforeach; ?>
    </ul>
  </nav>
<?php endforeach; ?>
  <div class="legal">
    <p>&copy; Fettle &amp; Co. A deliberately vulnerable test application.</p>
    <p class="meta">Registered in England. VAT GB 000 0000 00. Prices include VAT.</p>
    <p class="meta">Free delivery over &pound;50. Thirty-day returns on unused items.</p>
  </div>
</footer>
<div class="cookie-bar" data-cookie-bar hidden>
  <p>We use cookies to keep your basket and remember you are signed in.</p>
  <button class="btn-primary btn-sm" data-action="accept">Accept</button>
  <button class="btn-ghost btn-sm" data-action="decline">Decline</button>
</div>
</body>
</html>
<?php
}

/** A product card, including its image -- this is what makes the cascade. */
function product_card(array $p, int $position = 0): void
{
    $stock = (int) ($p['stock'] ?? 0);
    $rating = (float) ($p['rating'] ?? 0);
    $badge = $stock === 0 ? ['bad', 'Out of stock']
        : ($stock < 8 ? ['warn', 'Low stock'] : ['ok', 'In stock']);
    ?>
<article class="card" data-item data-product-id="<?= (int) $p['id'] ?>" data-position="<?= $position ?>">
  <a class="card-link" href="/p/<?= (int) $p['id'] ?>">
    <img src="/assets/img/p/<?= (int) $p['id'] ?>.jpg" alt="<?= e($p['name']) ?>" width="240" height="180" loading="lazy" decoding="async">
    <h3 class="card-title"><?= e($p['name']) ?></h3>
  </a>
  <p class="sku meta">SKU <?= e($p['sku'] ?? '') ?></p>
  <p class="rating" title="<?= number_format($rating, 1) ?> out of 5">
    <span class="stars" aria-hidden="true"><?= str_repeat('★', (int) round($rating)) ?><?= str_repeat('☆', 5 - (int) round($rating)) ?></span>
    <span class="meta"><?= number_format($rating, 1) ?></span>
  </p>
  <p class="price">&pound;<?= number_format((float) $p['price'], 2) ?></p>
  <p class="badge badge-<?= $badge[0] ?>"><?= $badge[1] ?></p>
  <div class="card-actions">
    <button class="add btn-primary btn-sm" data-product="<?= (int) $p['id'] ?>"<?= $stock === 0 ? ' disabled' : '' ?>>Add to basket</button>
    <button class="btn-ghost btn-sm" data-action="wishlist" data-product="<?= (int) $p['id'] ?>">Save</button>
  </div>
</article>
<?php
}

/**
 * ItemList structured data for a grid of products. Real listing pages carry
 * it, and it is a meaningful share of their weight.
 */
function product_list_ld(array $products, string $name): void
{
    json_ld([[
        '@context' => 'https://schema.org',
        '@type' => 'ItemList',
        'name' => $name,
        'numberOfItems' => count($products),
        'itemListElement' => array_map(
            static fn ($i, $p) => [
                '@type' => 'ListItem',
                'position' => $i + 1,
                'item' => [
                    '@type' => 'Product',
                    'name' => $p['name'],
                    'sku' => $p['sku'] ?? '',
                    'url' => 'http://shop.test/p/' . (int) $p['id'],
                    'image' => 'http://shop.test/assets/img/p/' . (int) $p['id'] . '.jpg',
                    'aggregateRating' => [
                        '@type' => 'AggregateRating',
                        'ratingValue' => round((float) ($p['rating'] ?? 0), 1),
                        'reviewCount' => 3 + ((int) $p['id'] % 180),
                    ],
                    'offers' => [
                        '@type' => 'Offer',
                        'price' => number_format((float) $p['price'], 2, '.', ''),
                        'priceCurrency' => 'GBP',
                        'availability' => ((int) ($p['stock'] ?? 0)) > 0
                            ? 'https://schema.org/InStock'
                            : 'https://schema.org/OutOfStock',
                    ],
                ],
            ],
            range(0, max(0, count($products) - 1)),
            $products
        ),
    ]]);
}
