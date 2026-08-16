<?php
/**
 * Hardened: prepared statement.
 *
 * The injectable search is /search, not this. Having both means the dataset
 * carries injection attempts that succeed and injection attempts that quietly
 * return nothing, which is what a real site looks like.
 */
require __DIR__ . '/../lib/db.php';

header('Content-Type: application/json');
$q = (string) ($_GET['q'] ?? '');
$matches = [];
if ($q !== '') {
    $st = db()->prepare(
        'SELECT id, name FROM products WHERE name LIKE ? ORDER BY rating DESC LIMIT 8');
    $st->execute(['%' . $q . '%']);
    $matches = $st->fetchAll();
}
echo json_encode(['q' => $q, 'matches' => $matches]);
