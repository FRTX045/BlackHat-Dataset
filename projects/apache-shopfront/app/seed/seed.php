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

function schema(PDO $pdo): void
{
    $pdo->exec('DROP TABLE IF EXISTS products');
    $pdo->exec('DROP TABLE IF EXISTS categories');
    $pdo->exec('CREATE TABLE categories (
        id INTEGER PRIMARY KEY, slug TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
        blurb TEXT NOT NULL)');
    $pdo->exec('CREATE TABLE products (
        id INTEGER PRIMARY KEY, category_id INTEGER NOT NULL, sku TEXT NOT NULL,
        name TEXT NOT NULL, description TEXT NOT NULL, price REAL NOT NULL,
        stock INTEGER NOT NULL, rating REAL NOT NULL)');
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
    $wide = 220 + (($id * 41) % 1180);
    $high = (int) ($wide * (0.62 + (($id * 11) % 40) / 100.0));
    $quality = 45 + (($id * 7) % 45);

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

foreach (["$root/data", "$root/assets/img/p", "$root/assets/fonts", "$root/uploads"] as $dir) {
    if (!is_dir($dir)) {
        mkdir($dir, 0o775, true);
    }
}

mt_srand(seed_value());

$pdo = new PDO('sqlite:' . $db_path);
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
schema($pdo);
$pdo->beginTransaction();
$ids = fill($pdo);
$pdo->commit();

foreach ($ids as $id) {
    $path = "$root/assets/img/p/$id.jpg";
    if (!file_exists($path)) {
        product_image($id, $path);
    }
}
icons($root);
fonts($root);

printf("seeded %d products across %d categories (seed %d)\n",
       count($ids), count(CATEGORIES), seed_value());
