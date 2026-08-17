#!/bin/sh
set -eu

# The application directory is bind-mounted from the repository, so it arrives
# owned by the host user. Apache serves as www-data (uid 33) and cannot write
# the SQLite database or the upload directory without this.
for dir in /var/www/html/data /var/www/html/uploads; do
    if [ -d "$dir" ]; then
        chown -R www-data:www-data "$dir"
    fi
done

# Build the catalogue and its assets if they are not there. Deterministic from
# LOGFORGE_SEED, and regenerated rather than committed: 130 product photographs
# are twenty-odd megabytes of binary that would bloat a public repository for
# no benefit, and the same seed reproduces them exactly.
# Run unconditionally: the seeder exits early when the database already matches
# its schema version, and rebuilds when it does not. A database seeded before a
# schema change would otherwise survive into the next run and make the
# application 404 on tables the code believes exist.
php /var/www/html/seed/seed.php
chown -R www-data:www-data /var/www/html/data /var/www/html/assets \
                           /var/www/html/uploads

# Start every run from empty logs. A build that inherited the previous run's
# lines would ship a log whose truth file describes a different run, and
# nothing downstream would notice: the line counts would still agree.
for log in access.log access.tagged.log error.log; do
    : > "/var/log/apache2/$log"
done

exec "$@"
