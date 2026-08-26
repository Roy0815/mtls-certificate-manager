#!/bin/sh
set -e

PUID="${PUID:-1000}"
PGID="${PGID:-1000}"

# linuxserver.io-style pattern: container starts as root so it can create a
# group/user with the caller-supplied ids and fix up ownership of the two
# bind-mounted volumes, then drops to that user for the actual node process.
# This is what makes files written into ./data and ./pki come out owned by
# the host user that mounted them, instead of some arbitrary image-build uid.
if ! getent group "$PGID" >/dev/null 2>&1; then
  addgroup -g "$PGID" appgroup
fi
GROUP_NAME="$(getent group "$PGID" | cut -d: -f1)"

if ! getent passwd "$PUID" >/dev/null 2>&1; then
  adduser -D -H -u "$PUID" -G "$GROUP_NAME" appuser
fi
USER_NAME="$(getent passwd "$PUID" | cut -d: -f1)"

mkdir -p /app/data /app/pki
chown -R "$PUID:$PGID" /app/data /app/pki

exec su-exec "$PUID:$PGID" node src/server.js
