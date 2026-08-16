FROM php:8.3-apache

# a2disconf other-vhosts-access-log: Debian ships a third access log, and
#   server/logs/ must hold exactly the three files the dataset is made of.
# rm 000-default.conf: it defines its own CustomLog, which would shadow ours.
# rm /var/log/apache2/*.log: the base image symlinks them to /dev/stdout and
#   /dev/stderr. The dataset is the file Apache writes, so the symlinks have to
#   go -- otherwise every line lands in Docker's log driver and the
#   bind-mounted file stays empty.
RUN apt-get update \
 && apt-get install -y --no-install-recommends libsqlite3-dev \
 && rm -rf /var/lib/apt/lists/* \
 && docker-php-ext-install pdo pdo_sqlite \
 && a2enmod remoteip rewrite headers deflate \
 && a2disconf other-vhosts-access-log \
 && rm -f /etc/apache2/sites-enabled/000-default.conf \
 && rm -f /var/log/apache2/*.log

COPY zz-logforge.conf /etc/apache2/conf-enabled/zz-logforge.conf
COPY vhost.conf       /etc/apache2/sites-enabled/shopfront.conf
COPY entrypoint.sh    /usr/local/bin/logforge-entrypoint

RUN chmod +x /usr/local/bin/logforge-entrypoint

ENTRYPOINT ["/usr/local/bin/logforge-entrypoint"]
CMD ["apache2-foreground"]
