#!/usr/bin/env bash
# Bootstrap a real Let's Encrypt cert on first deploy.
# Run this ONCE on the server after DNS is pointing at the box and ports 80/443 are open.
#
# Usage:  DOMAIN=mailbox.example.com EMAIL=you@example.com ./docker/init-letsencrypt.sh
set -euo pipefail

: "${DOMAIN:?Set DOMAIN, e.g. DOMAIN=mailbox.example.com}"
: "${EMAIL:?Set EMAIL, e.g. EMAIL=you@example.com}"

# Set to 1 to use Let's Encrypt's staging server (no rate limit; cert not trusted by browsers).
STAGING="${STAGING:-0}"

DATA_PATH="./docker/certbot"
LIVE_PATH="$DATA_PATH/conf/live/$DOMAIN"

mkdir -p "$DATA_PATH/conf" "$DATA_PATH/www"

# Sub YOUR_DOMAIN -> real domain in the mounted nginx config.
# (We sed the file in-place; safe because it's mounted read-only into the container, not read-only on disk.)
sed -i "s/YOUR_DOMAIN/$DOMAIN/g" docker/nginx/conf.d/app.conf

if [ ! -e "$LIVE_PATH/fullchain.pem" ]; then
  echo "### Creating dummy cert so nginx can boot..."
  mkdir -p "$LIVE_PATH"
  docker compose run --rm --entrypoint "\
    openssl req -x509 -nodes -newkey rsa:2048 -days 1 \
      -keyout '/etc/letsencrypt/live/$DOMAIN/privkey.pem' \
      -out    '/etc/letsencrypt/live/$DOMAIN/fullchain.pem' \
      -subj '/CN=localhost'" certbot
fi

echo "### Starting nginx..."
docker compose up -d nginx web

echo "### Deleting dummy cert..."
docker compose run --rm --entrypoint "\
  rm -Rf /etc/letsencrypt/live/$DOMAIN \
  && rm -Rf /etc/letsencrypt/archive/$DOMAIN \
  && rm -Rf /etc/letsencrypt/renewal/$DOMAIN.conf" certbot

echo "### Requesting real Let's Encrypt cert for $DOMAIN..."
STAGING_FLAG=""
[ "$STAGING" = "1" ] && STAGING_FLAG="--staging"

docker compose run --rm --entrypoint "\
  certbot certonly --webroot -w /var/www/certbot \
    $STAGING_FLAG \
    --email $EMAIL \
    -d $DOMAIN \
    --rsa-key-size 2048 \
    --agree-tos \
    --no-eff-email \
    --force-renewal" certbot

echo "### Reloading nginx..."
docker compose exec nginx nginx -s reload

echo "### Done. https://$DOMAIN should be live."
