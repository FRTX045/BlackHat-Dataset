<?php
/**
 * Serve a shop document.
 *
 * PLANTED WEAKNESS 3 -- path traversal.
 *
 * The requested name is joined onto the documents directory with no
 * normalisation and no check that the result stayed inside it, so ../ escapes.
 * See app/VULNERABILITIES.md.
 */

$file = (string) ($_GET['file'] ?? '');
if ($file === '') {
    http_response_code(400);
    header('Content-Type: text/plain');
    echo "name a document\n";
    return;
}

$path = __DIR__ . '/lib/docs/' . $file;
$body = @file_get_contents($path);

if ($body === false) {
    http_response_code(404);
    require __DIR__ . '/404.php';
    return;
}

header('Content-Type: text/plain; charset=utf-8');
echo $body;
