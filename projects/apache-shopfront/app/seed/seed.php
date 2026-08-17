<?php
/**
 * Build the catalogue and its assets, deterministically from the run seed.
 *
 * Run once by the container entrypoint. Everything it writes is regenerated
 * rather than committed: 130 product photographs are twenty-odd megabytes of
 * binary that would bloat a public repository for no benefit, and the same
 * seed reproduces them byte for byte anyway.
 *
 * The images are real JPEGs at genuinely different dimensions, not padded
 * placeholder bytes, because %b is a field consumers will study and a
 * catalogue where every photograph is the same size teaches something false.
 */

/**
 * Bumped whenever the schema changes.
 *
 * The entrypoint runs this script on every start and it exits early when the
 * database already matches. Without the check, a database seeded before a
 * schema change survives into the next run and the application 404s or 500s
 * on tables that the code believes exist -- which costs an hour to diagnose
 * and looks like an application bug rather than a stale file.
 */
const SCHEMA_VERSION = 2;

const CATEGORIES = [
    ['hand-tools',   'Hand Tools',        ['Chisel', 'Mallet', 'Hacksaw', 'Rasp', 'Spokeshave', 'Bradawl', 'Plane', 'Scriber']],
    ['power-tools',  'Power Tools',       ['Drill', 'Sander', 'Jigsaw', 'Router', 'Grinder', 'Nailer', 'Planer', 'Multitool']],
    ['garden',       'Garden',            ['Spade', 'Trowel', 'Secateurs', 'Loppers', 'Dibber', 'Riddle', 'Hoe', 'Edger']],
    ['kitchen',      'Kitchen',           ['Skillet', 'Stockpot', 'Colander', 'Whisk', 'Mandoline', 'Ramekin', 'Cleaver', 'Trivet']],
    ['lighting',     'Lighting',          ['Downlight', 'Pendant', 'Bollard', 'Floodlight', 'Sconce', 'Uplighter', 'Batten', 'Lantern']],
    ['storage',      'Storage',           ['Toolbox', 'Crate', 'Shelf', 'Caddy', 'Locker', 'Trunk', 'Rack', 'Bin']],
    ['safety',       'Safety',            ['Goggles', 'Respirator', 'Gauntlets', 'Harness', 'Earmuffs', 'Visor', 'Kneepads', 'Lanyard']],
    ['fasteners',    'Fasteners',         ['Coachbolt', 'Woodscrew', 'Rivet', 'Anchor', 'Washer', 'Dowel', 'Bracket', 'Clip']],
    ['decorating',   'Decorating',        ['Roller', 'Brushset', 'Filler', 'Sealant', 'Stripper', 'Sandblock', 'Trestle', 'Dustsheet']],
    ['electrical',   'Electrical',        ['Backbox', 'Conduit', 'Junction', 'Dimmer', 'Socket', 'Consumer', 'Ferrule', 'Gland']],
];

const MATERIALS = ['Oak', 'Brass', 'Forged', 'Stainless', 'Copper', 'Ash', 'Cast Iron',
                   'Galvanised', 'Titanium', 'Beech', 'Bronze', 'Carbon'];
const RANGES = ['Yardsman', 'Cobble', 'Ferrier', 'Kestrel', 'Ledgerwood', 'Marram',
                'Ninebark', 'Quarrel', 'Sable', 'Thistledown'];

function seed_value(): int
{
    return (int) (getenv('LOGFORGE_SEED') ?: 7);
}

/**
 * Seeded accounts.
 *
 * Every credential here is invented and weak on purpose, so a brute-force run
 * against this shop finds something. None of these is a real credential for
 * anything, and the application is never reachable outside its lab network.
 */
const USERS = [
    ['demo',    'demo@shop.test',    'demo123',   'customer'],
    ['rmarsh',  'r.marsh@shop.test', 'hunter2',   'customer'],
    ['pcollis', 'p.collis@shop.test', 'letmein1', 'customer'],
    ['agatha',  'agatha@shop.test',  'brassneck', 'admin'],
];

function schema(PDO $pdo): void
{
    $pdo->exec('DROP TABLE IF EXISTS order_items');
    $pdo->exec('DROP TABLE IF EXISTS orders');
    $pdo->exec('DROP TABLE IF EXISTS addresses');
    $pdo->exec('DROP TABLE IF EXISTS login_attempts');
    $pdo->exec('DROP TABLE IF EXISTS users');
    $pdo->exec('DROP TABLE IF EXISTS products');
    $pdo->exec('DROP TABLE IF EXISTS categories');
    $pdo->exec('CREATE TABLE categories (
        id INTEGER PRIMARY KEY, slug TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
        blurb TEXT NOT NULL)');
    $pdo->exec('CREATE TABLE products (
        id INTEGER PRIMARY KEY, category_id INTEGER NOT NULL, sku TEXT NOT NULL,
        name TEXT NOT NULL, description TEXT NOT NULL, price REAL NOT NULL,
        stock INTEGER NOT NULL, rating REAL NOT NULL)');
    $pdo->exec('CREATE TABLE users (
        id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL,
        email TEXT NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL,
        avatar TEXT)');
    $pdo->exec('CREATE TABLE login_attempts (
        username TEXT PRIMARY KEY, failures INTEGER NOT NULL,
        locked_until INTEGER NOT NULL DEFAULT 0)');
    $pdo->exec('CREATE TABLE addresses (
        id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, label TEXT NOT NULL,
        line1 TEXT NOT NULL, city TEXT NOT NULL, postcode TEXT NOT NULL)');
    // Sequential integer order ids across all customers, on purpose: they are
    // what makes walking them a plausible thing to try, and what makes the
    // resulting run of 200s legible in the access log.
    $pdo->exec('CREATE TABLE orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
        placed_at TEXT NOT NULL, total REAL NOT NULL, status TEXT NOT NULL)');
    $pdo->exec('CREATE TABLE order_items (
        id INTEGER PRIMARY KEY, order_id INTEGER NOT NULL,
        product_id INTEGER NOT NULL, quantity INTEGER NOT NULL, price REAL NOT NULL)');
}

function accounts(PDO $pdo, int $product_count): void
{
    $ins = $pdo->prepare(
        'INSERT INTO users (id, username, email, password_hash, role)
         VALUES (?, ?, ?, ?, ?)');
    foreach (USERS as $i => [$username, $email, $password, $role]) {
        $ins->execute([$i + 1, $username, $email,
                       password_hash($password, PASSWORD_DEFAULT), $role]);
    }

    $addr = $pdo->prepare(
        'INSERT INTO addresses (user_id, label, line1, city, postcode)
         VALUES (?, ?, ?, ?, ?)');
    $towns = [['Ashby Lane', 'Kettleby', 'KT4 9PN'], ['Mill Row', 'Harnwood', 'HW2 3RD'],
              ['Quarry Rise', 'Stanmoor', 'SM7 1LX']];
    foreach (USERS as $i => $_) {
        [$line1, $city, $postcode] = $towns[$i % count($towns)];
        $addr->execute([$i + 1, 'Home', ($i + 3) . ' ' . $line1, $city, $postcode]);
    }

    $order = $pdo->prepare(
        'INSERT INTO orders (user_id, placed_at, total, status) VALUES (?, ?, ?, ?)');
    $item = $pdo->prepare(
        'INSERT INTO order_items (order_id, product_id, quantity, price)
         VALUES (?, ?, ?, ?)');
    $statuses = ['delivered', 'delivered', 'dispatched', 'packing', 'cancelled'];

    // Interleaved across customers so the sequential ids do not simply group by
    // owner -- an attacker walking them lands on other people's orders, which
    // is the whole point of the surface.
    for ($round = 0; $round < 4; $round++) {
        foreach (USERS as $i => $_) {
            $user_id = $i + 1;
            $total = round(18.0 + (($user_id * 137 + $round * 53) % 3600) / 10.0, 2);
            $order->execute([
                $user_id,
                sprintf('2026-0%d-%02d 1%d:04:00', 3 + $round, 7 + $user_id, $round),
                $total, $statuses[($user_id + $round) % count($statuses)]]);
            $order_id = (int) $pdo->lastInsertId();
            for ($n = 0; $n < 1 + (($user_id + $round) % 3); $n++) {
                $item->execute([$order_id,
                    1 + (($user_id * 31 + $round * 17 + $n * 7) % $product_count),
                    1 + $n, round(6.0 + (($order_id * 29 + $n) % 900) / 10.0, 2)]);
            }
        }
    }
}

function fill(PDO $pdo): array
{
    $cat = $pdo->prepare(
        'INSERT INTO categories (id, slug, name, blurb) VALUES (?, ?, ?, ?)');
    $prod = $pdo->prepare(
        'INSERT INTO products (id, category_id, sku, name, description, price, stock, rating)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)');

    $product_id = 0;
    $written = [];
    foreach (CATEGORIES as $index => [$slug, $name, $nouns]) {
        $category_id = $index + 1;
        $cat->execute([$category_id, $slug, $name,
            "Everything in {$name}, chosen by people who use it."]);

        // Thirteen per category gives 130 products across 10 categories -- past
        // the 120 the plan asks for, with a URL vocabulary wide enough that a
        // directory brute-forcer does not exhaust it in a hundred requests.
        for ($n = 0; $n < 13; $n++) {
            $product_id++;
            $noun = $nouns[$n % count($nouns)];
            $material = MATERIALS[($product_id * 7) % count(MATERIALS)];
            $range = RANGES[($product_id * 3) % count(RANGES)];
            $label = "{$range} {$material} {$noun}";
            $price = round(4.5 + (($product_id * 137) % 4200) / 10.0, 2);
            $stock = ($product_id * 17) % 240;
            $rating = round(2.6 + (($product_id * 29) % 24) / 10.0, 1);
            $prod->execute([
                $product_id, $category_id,
                sprintf('%s-%04d', strtoupper(substr($slug, 0, 3)), $product_id),
                $label,
                "The {$label} is part of our {$range} range. Solid {$material} "
                . "throughout, sized for daily use rather than the drawer.",
                $price, $stock, $rating,
            ]);
            $written[] = $product_id;
        }
    }
    return $written;
}

/** A real JPEG whose size depends on the product, spanning roughly 8KB-900KB. */
function product_image(int $id, string $path): void
{
    // Dimensions and noise density both vary, so the size distribution is
    // genuinely spread rather than two clusters.
    //
    // Retuned after measuring a shipped build: the median came out at 132 KB
    // with a 752 KB tail, which is what a badly-built shop serves but put the
    // median page weight above 1.6 MB of images alone. Real product imagery
    // on a listing is 15-80 KB and a detail shot 80-250 KB, so the top of the
    // range is pulled in and the middle brought down. The tail is kept --
    // every real shop has a handful of images nobody optimised.
    $wide = 200 + (($id * 41) % 820);
    $high = (int) ($wide * (0.62 + (($id * 11) % 40) / 100.0));
    $quality = 38 + (($id * 7) % 42);

    $img = imagecreatetruecolor($wide, $high);
    $blocks = 8 + ($id % 40);
    for ($i = 0; $i < $blocks; $i++) {
        $colour = imagecolorallocate(
            $img, ($id * ($i + 3) * 13) % 256,
            ($id * ($i + 5) * 29) % 256, ($id * ($i + 7) * 47) % 256);
        imagefilledrectangle(
            $img, ($i * 37) % $wide, ($i * 53) % $high,
            (($i * 37) % $wide) + (int) ($wide / 3),
            (($i * 53) % $high) + (int) ($high / 3), $colour);
    }
    // Fine detail defeats JPEG's compression unevenly, which is what actually
    // spreads the byte sizes out. Sparser on the larger images, so the top of
    // the range stays near 900KB rather than running away to several MB.
    $step = 3 + (int) ($wide / 700);
    for ($y = 0; $y < $high; $y += $step) {
        for ($x = 0; $x < $wide; $x += $step) {
            $c = imagecolorallocate($img, ($x * $y * $id) % 256,
                                    ($x + $y + $id) % 256, ($x * 3 + $y * 5) % 256);
            imagesetpixel($img, $x, $y, $c);
        }
    }
    imagejpeg($img, $path, $quality);
    imagedestroy($img);
}

function icons(string $root): void
{
    $logo = imagecreatetruecolor(132, 32);
    imagefilledrectangle($logo, 0, 0, 132, 32, imagecolorallocate($logo, 26, 42, 58));
    imagestring($logo, 5, 8, 8, 'FETTLE & CO', imagecolorallocate($logo, 245, 245, 245));
    imagepng($logo, "$root/assets/img/logo.png");
    imagedestroy($logo);

    $touch = imagecreatetruecolor(180, 180);
    imagefilledrectangle($touch, 0, 0, 180, 180, imagecolorallocate($touch, 26, 42, 58));
    imagestring($touch, 5, 60, 84, 'F&C', imagecolorallocate($touch, 245, 245, 245));
    imagepng($touch, "$root/apple-touch-icon.png");
    imagedestroy($touch);

    // A 16x16 BMP-backed ICO, hand-assembled: GD cannot write .ico and the
    // favicon request is one every real browser makes unprompted.
    $pixels = '';
    for ($y = 15; $y >= 0; $y--) {
        for ($x = 0; $x < 16; $x++) {
            $pixels .= pack('CCCC', 58, 42, 26, 255);
        }
    }
    $dib = pack('VVVvvVVVVVV', 40, 16, 32, 1, 32, 0, strlen($pixels), 0, 0, 0, 0);
    $image = $dib . $pixels . str_repeat("\0", 64);
    $header = pack('vvv', 0, 1, 1)
            . pack('CCCCvvVV', 16, 16, 0, 0, 1, 32, strlen($image), 22);
    file_put_contents("$root/favicon.ico", $header . $image);
}

/**
 * Placeholder webfonts.
 *
 * These carry a valid wOF2 signature and deterministic padding, and are NOT
 * real fonts. The requests, responses and byte counts in the log are genuine;
 * the glyphs are not, so headless Chromium falls back to a system face. Stated
 * plainly in the dataset's Known Limitations rather than left to be discovered.
 */
function fonts(string $root): void
{
    foreach (['inter-400' => 24_500, 'inter-600' => 26_900] as $name => $size) {
        $body = '';
        for ($i = 0; strlen($body) < $size; $i++) {
            $body .= pack('N', ($i * 2654435761) % 4294967296);
        }
        file_put_contents("$root/assets/fonts/$name.woff2",
                          'wOF2' . substr($body, 0, $size - 4));
    }
}

// ---------------------------------------------------------------------------

$root = getenv('LOGFORGE_APP_ROOT') ?: '/var/www/html';
$db_path = getenv('LOGFORGE_DB') ?: "$root/data/catalogue.sqlite";

foreach (["$root/data", "$root/assets/img/p", "$root/assets/fonts",
          "$root/assets/css", "$root/assets/js", "$root/uploads"] as $dir) {
    if (!is_dir($dir)) {
        mkdir($dir, 0o775, true);
    }
}

mt_srand(seed_value());

/*
 * Static assets first, and outside the schema guard.
 *
 * These are generated rather than committed -- the repository carries the
 * recipe -- so a fresh clone starts with no stylesheets, no scripts, no
 * product images and no fonts. Every one of them is cheap to skip when it is
 * already there, and expensive to be missing: Apache answers a request for an
 * absent stylesheet with the 404 page, which is a 7 KB HTML document with no
 * ETag, and the dataset fills up with 404s for assets that should exist.
 *
 * This used to sit *after* the guard below, so a container whose database was
 * already at the current schema would exit before regenerating anything. That
 * is exactly what a fresh checkout looks like once the assets are gitignored,
 * and it turned three container-backed tests red in a way that pointed at
 * Apache rather than at the seeder.
 */
require __DIR__ . '/assets.php';
if (!file_exists("$root/assets/css/site.css")) {
    stylesheets($root);
}
if (!file_exists("$root/assets/js/app.js")) {
    scripts($root);
}
if (!file_exists("$root/assets/fonts/inter-400.woff2")) {
    fonts($root);
}
if (!file_exists("$root/favicon.ico")) {
    icons($root);
}

$pdo = new PDO('sqlite:' . $db_path);
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

if ((int) $pdo->query('PRAGMA user_version')->fetchColumn() === SCHEMA_VERSION
    && !in_array('--force', $argv, true)) {
    // The product images depend on the catalogue, so they are checked here
    // rather than above -- but they still have to be checked, for the same
    // reason.
    foreach ($pdo->query('SELECT id FROM products')->fetchAll() as $row) {
        $path = "$root/assets/img/p/" . (int) $row['id'] . ".jpg";
        if (!file_exists($path)) {
            product_image((int) $row['id'], $path);
        }
    }
    echo "catalogue already at schema " . SCHEMA_VERSION . "\n";
    exit(0);
}

schema($pdo);
$pdo->beginTransaction();
$ids = fill($pdo);
accounts($pdo, count($ids));
$pdo->commit();

foreach ($ids as $id) {
    $path = "$root/assets/img/p/$id.jpg";
    if (!file_exists($path)) {
        product_image($id, $path);
    }
}
// A --force run regenerates the static assets too, so a change to their
// generator takes effect without anybody having to delete files by hand.
icons($root);
fonts($root);
stylesheets($root);
scripts($root);

$pdo->exec('PRAGMA user_version = ' . SCHEMA_VERSION);

/*
 * Publish the shape of the catalogue for the traffic driver.
 *
 * The driver has to know which products live in which category, or it cannot
 * plan a journey that is possible -- and asking the running server for that
 * would put harness requests in the dataset. Written beside the database, in
 * the repository tree both containers mount.
 */
$manifest = ['categories' => [], 'users' => []];
foreach ($pdo->query('SELECT id, slug FROM categories ORDER BY id') as $c) {
    $in_category = $pdo->prepare(
        'SELECT id FROM products WHERE category_id = ? ORDER BY id');
    $in_category->execute([$c['id']]);
    $manifest['categories'][] = [
        'slug' => $c['slug'],
        'products' => array_map('intval',
                                $in_category->fetchAll(PDO::FETCH_COLUMN)),
    ];
}
foreach (USERS as [$username, $email, $password, $role]) {
    $orders = $pdo->prepare(
        'SELECT o.id FROM orders o JOIN users u ON u.id = o.user_id
          WHERE u.username = ? ORDER BY o.id');
    $orders->execute([$username]);
    $manifest['users'][] = [
        'username' => $username,
        // Present so the driver can sign in as a real customer. These are the
        // same invented credentials seeded above; nothing here is a secret.
        'password' => $password,
        'role' => $role,
        'orders' => array_map('intval', $orders->fetchAll(PDO::FETCH_COLUMN)),
    ];
}
file_put_contents("$root/data/catalogue.json",
                  json_encode($manifest, JSON_PRETTY_PRINT) . "\n");

printf("seeded %d products across %d categories and %d accounts (seed %d, schema %d)\n",
       count($ids), count(CATEGORIES), count(USERS), seed_value(), SCHEMA_VERSION);
