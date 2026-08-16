<?php
/**
 * Session handling.
 *
 * A plain PHP session cookie, so the log carries the same repeat-visitor
 * shape a real shop's does. Task 10 builds the account area on top of this.
 */

function start_session(): void
{
    if (session_status() === PHP_SESSION_NONE) {
        session_set_cookie_params(['httponly' => true, 'samesite' => 'Lax']);
        session_start();
    }
}

function current_user(): ?array
{
    start_session();
    return $_SESSION['user'] ?? null;
}

function require_login(): array
{
    $user = current_user();
    if ($user === null) {
        header('Location: /login?next=' . urlencode($_SERVER['REQUEST_URI'] ?? '/'));
        http_response_code(302);
        exit;
    }
    return $user;
}
