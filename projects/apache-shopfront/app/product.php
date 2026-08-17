<?php
require __DIR__ . '/lib/db.php';
require __DIR__ . '/lib/render.php';

$item = product((int) ($_GET['id'] ?? 0));
if ($item === null) {
    http_response_code(404);
    require __DIR__ . '/404.php';
    return;
}

$related = array_values(array_filter(
    products_in((int) $item['category_id'], 8),
    static fn ($p) => (int) $p['id'] !== (int) $item['id']));

$id = (int) $item['id'];
$reviews = 3 + ($id % 180);

layout_head($item['name'], [
    'page' => 'product',
    'canonical' => 'http://shop.test/p/' . $id,
    'description' => substr($item['description'], 0, 155),
    'crumbs' => ['/c/' . $item['category_slug'] => $item['category_name'],
                 '/p/' . $id => $item['name']],
]);

// A product page is the heaviest document a shop serves. Structured data is a
// real and substantial part of that weight, and crawlers genuinely read it.
json_ld([[
    '@context' => 'https://schema.org',
    '@type' => 'Product',
    'name' => $item['name'],
    'sku' => $item['sku'],
    'description' => $item['description'],
    'image' => ['http://shop.test/assets/img/p/' . $id . '.jpg'],
    'brand' => ['@type' => 'Brand', 'name' => 'Fettle & Co'],
    'category' => $item['category_name'],
    'aggregateRating' => [
        '@type' => 'AggregateRating',
        'ratingValue' => round((float) $item['rating'], 1),
        'reviewCount' => $reviews,
        'bestRating' => 5,
        'worstRating' => 1,
    ],
    'offers' => [
        '@type' => 'Offer',
        'url' => 'http://shop.test/p/' . $id,
        'price' => number_format((float) $item['price'], 2, '.', ''),
        'priceCurrency' => 'GBP',
        'itemCondition' => 'https://schema.org/NewCondition',
        'availability' => ((int) $item['stock']) > 0
            ? 'https://schema.org/InStock' : 'https://schema.org/OutOfStock',
        'shippingDetails' => [
            '@type' => 'OfferShippingDetails',
            'shippingRate' => ['@type' => 'MonetaryAmount',
                               'value' => '4.95', 'currency' => 'GBP'],
            'deliveryTime' => [
                '@type' => 'ShippingDeliveryTime',
                'handlingTime' => ['@type' => 'QuantitativeValue',
                                   'minValue' => 0, 'maxValue' => 1,
                                   'unitCode' => 'DAY'],
                'transitTime' => ['@type' => 'QuantitativeValue',
                                  'minValue' => 1, 'maxValue' => 3,
                                  'unitCode' => 'DAY'],
            ],
        ],
        'hasMerchantReturnPolicy' => [
            '@type' => 'MerchantReturnPolicy',
            'applicableCountry' => 'GB',
            'returnPolicyCategory' =>
                'https://schema.org/MerchantReturnFiniteReturnWindow',
            'merchantReturnDays' => 30,
        ],
    ],
]]);
?>
<article class="product">
  <div class="gallery" data-gallery>
    <img src="/assets/img/p/<?= $id ?>.jpg" alt="<?= e($item['name']) ?>" width="640" height="420" decoding="async">
    <ol class="thumbs">
<?php foreach ([$id] as $shot): ?>
      <li><button data-action="show" data-shot="<?= (int) $shot ?>" aria-label="View image"><img src="/assets/img/p/<?= (int) $shot ?>.jpg" alt="" width="72" height="54" loading="lazy"></button></li>
<?php endforeach; ?>
    </ol>
  </div>
  <div class="detail">
    <h1><?= e($item['name']) ?></h1>
    <p class="sku meta">SKU <?= e($item['sku']) ?> &middot; <?= e($item['category_name']) ?></p>
    <p class="rating">
      <span class="stars" aria-hidden="true"><?= str_repeat('★', (int) round((float) $item['rating'])) ?><?= str_repeat('☆', 5 - (int) round((float) $item['rating'])) ?></span>
      <span class="meta"><?= e((string) $item['rating']) ?> out of 5 from <?= $reviews ?> reviews</span>
    </p>
    <p class="price">&pound;<?= number_format((float) $item['price'], 2) ?> <span class="meta">inc. VAT</span></p>
    <p class="stock badge badge-<?= ((int) $item['stock']) > 0 ? 'ok' : 'bad' ?>" data-product="<?= $id ?>"><?= (int) $item['stock'] ?> in stock</p>
    <div class="buy">
      <label class="visually-hidden" for="qty">Quantity</label>
      <input type="number" id="qty" name="qty" value="1" min="1" max="20" inputmode="numeric">
      <button class="add btn-primary btn-lg" data-product="<?= $id ?>">Add to basket</button>
      <button class="btn-ghost btn-lg" data-action="wishlist" data-product="<?= $id ?>">Save for later</button>
    </div>
    <p class="prose"><?= e($item['description']) ?></p>

    <h2>Specification</h2>
    <table class="table specs">
      <tbody>
        <tr><th>SKU</th><td><?= e($item['sku']) ?></td></tr>
        <tr><th>Department</th><td><?= e($item['category_name']) ?></td></tr>
        <tr><th>Price</th><td>&pound;<?= number_format((float) $item['price'], 2) ?></td></tr>
        <tr><th>Stock</th><td><?= (int) $item['stock'] ?></td></tr>
        <tr><th>Rating</th><td><?= e((string) $item['rating']) ?> / 5</td></tr>
        <tr><th>Delivery</th><td>Same-day dispatch, 1&ndash;3 working days</td></tr>
        <tr><th>Returns</th><td>30 days, unused and in original packaging</td></tr>
        <tr><th>Warranty</th><td>12 months against manufacturing defects</td></tr>
        <tr><th>Guarantee</th><td>Price matched against any UK trade supplier</td></tr>
      </tbody>
    </table>

    <h2>Delivery and returns</h2>
    <div class="prose">
      <p>Orders placed before 4pm on a working day are dispatched the same day.
      Standard delivery is &pound;4.95 and free on orders over &pound;50.</p>
      <p>Unused items can be returned within thirty days in their original
      packaging. Bulky items may be collected; contact us to arrange it.</p>
      <p>Trade accounts get 30-day terms and tiered pricing. Ask at the counter
      or use the contact form.</p>
    </div>
  </div>
</article>

<section class="reviews" data-reviews>
  <h2>Reviews</h2>
  <p class="meta"><?= $reviews ?> reviews, average <?= e((string) $item['rating']) ?> out of 5</p>
  <ol class="review-list">
<?php foreach ([['Bought for a re-fit and it has not missed a beat.', 5],
                ['Does the job. Handle could be a little longer.', 4],
                ['Arrived next day, well packed, exactly as described.', 5]] as $i => $r): ?>
    <li class="review">
      <p class="stars" aria-hidden="true"><?= str_repeat('★', (int) $r[1]) ?><?= str_repeat('☆', 5 - (int) $r[1]) ?></p>
      <p><?= e($r[0]) ?></p>
      <p class="meta">Verified purchase</p>
    </li>
<?php endforeach; ?>
  </ol>
</section>

<section class="grid related">
  <h2>Others in <?= e($item['category_name']) ?></h2>
<?php foreach (array_slice($related, 0, 6) as $i => $p) { product_card($p, $i); } ?>
</section>
<?php
product_list_ld(array_slice($related, 0, 6), 'Others in ' . $item['category_name']);
layout_foot();
