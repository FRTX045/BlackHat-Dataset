<?php
/**
 * The catalogue database.
 *
 * SQLite, because the shop has to be a real application with real queries --
 * a planted SQL injection is only worth planting if there is a real query
 * engine behind it -- without adding a second container to the topology.
 */

function db(): PDO
{
    static $pdo = null;
    if ($pdo === null) {
        $path = getenv('LOGFORGE_DB') ?: '/var/www/html/data/catalogue.sqlite';
        $pdo = new PDO('sqlite:' . $path);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
    }
    return $pdo;
}

function categories(): array
{
    return db()->query('SELECT * FROM categories ORDER BY name')->fetchAll();
}

function category_by_slug(string $slug): ?array
{
    $st = db()->prepare('SELECT * FROM categories WHERE slug = ?');
    $st->execute([$slug]);
    return $st->fetch() ?: null;
}

function products_in(int $category_id, int $limit = 24): array
{
    $st = db()->prepare(
        'SELECT * FROM products WHERE category_id = ? ORDER BY name LIMIT ?');
    $st->execute([$category_id, $limit]);
    return $st->fetchAll();
}

function product(int $id): ?array
{
    $st = db()->prepare(
        'SELECT p.*, c.slug AS category_slug, c.name AS category_name
           FROM products p JOIN categories c ON c.id = p.category_id
          WHERE p.id = ?');
    $st->execute([$id]);
    return $st->fetch() ?: null;
}

function featured(int $limit = 12): array
{
    $st = db()->prepare('SELECT * FROM products ORDER BY rating DESC, id LIMIT ?');
    $st->execute([$limit]);
    return $st->fetchAll();
}

function all_products(): array
{
    return db()->query('SELECT id FROM products ORDER BY id')->fetchAll();
}
