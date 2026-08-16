<?php
require __DIR__ . '/lib/session.php';
start_session();
$_SESSION = [];
session_destroy();
header('Location: /');
http_response_code(302);
