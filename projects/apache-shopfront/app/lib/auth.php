<?php
/**
 * Credentials and roles.
 *
 * Deliberately competent: bcrypt hashes, prepared statements, and a lockout
 * after repeated failures. The weaknesses in this application are planted in
 * specific documented places, not spread everywhere -- a lab where every
 * attack succeeds teaches something false, so credential-stuffing traffic in
 * the dataset needs somewhere to fail.
 */
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/session.php';

const LOCKOUT_AFTER = 5;
const LOCKOUT_SECONDS = 900;

function user_by_username(string $username): ?array
{
    $st = db()->prepare('SELECT * FROM users WHERE username = ?');
    $st->execute([$username]);
    return $st->fetch() ?: null;
}

function is_locked_out(string $username): bool
{
    $st = db()->prepare('SELECT locked_until FROM login_attempts WHERE username = ?');
    $st->execute([$username]);
    $row = $st->fetch();
    return $row !== false && (int) $row['locked_until'] > time();
}

function record_failure(string $username): void
{
    $pdo = db();
    $st = $pdo->prepare('SELECT failures FROM login_attempts WHERE username = ?');
    $st->execute([$username]);
    $row = $st->fetch();
    $failures = ($row === false ? 0 : (int) $row['failures']) + 1;
    $until = $failures >= LOCKOUT_AFTER ? time() + LOCKOUT_SECONDS : 0;

    $up = $pdo->prepare(
        'INSERT INTO login_attempts (username, failures, locked_until)
         VALUES (:u, :f, :l)
         ON CONFLICT(username) DO UPDATE SET failures = :f, locked_until = :l');
    $up->execute([':u' => $username, ':f' => $failures, ':l' => $until]);
}

function clear_failures(string $username): void
{
    $st = db()->prepare('DELETE FROM login_attempts WHERE username = ?');
    $st->execute([$username]);
}

/** Returns the user on success, or null. Locked accounts never match. */
function attempt_login(string $username, string $password): ?array
{
    $user = user_by_username($username);
    if ($user === null || !password_verify($password, $user['password_hash'])) {
        record_failure($username);
        return null;
    }
    clear_failures($username);
    start_session();
    session_regenerate_id(true);
    $_SESSION['user'] = [
        'id' => (int) $user['id'],
        'username' => $user['username'],
        'role' => $user['role'],
    ];
    return $_SESSION['user'];
}

function is_admin(): bool
{
    $user = current_user();
    return $user !== null && $user['role'] === 'admin';
}

/**
 * The enforced role check.
 *
 * Applied by /admin/users and /admin/orders and NOT by the other admin
 * routes. That split is deliberate and documented in VULNERABILITIES.md: the
 * dataset needs forced-browsing attempts that get a 403 as well as ones that
 * get through.
 */
function require_admin(): array
{
    $user = require_login();
    if ($user['role'] !== 'admin') {
        http_response_code(403);
        require __DIR__ . '/../403.php';
        exit;
    }
    return $user;
}
