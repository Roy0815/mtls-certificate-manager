# --- builder ---------------------------------------------------------------
# argon2 is a native addon (node-gyp); build it here so the runtime image
# doesn't need a C toolchain at all.
FROM node:22-alpine AS builder

RUN apk add --no-cache python3 make g++

WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install --omit=dev

# --- runtime -----------------------------------------------------------------
FROM node:22-alpine

# su-exec: drops from root to the PUID/PGID user before starting node,
# linuxserver.io-style, so bind-mounted ./data and ./pki end up owned by
# the host user instead of a fixed image uid.
RUN apk add --no-cache su-exec

WORKDIR /app
COPY --from=builder /app/node_modules ./node_modules
COPY package.json ./
COPY cli.js ./
COPY src ./src
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENV NODE_ENV=production \
    PORT=3000 \
    CERT_VALIDITY_DAYS=365

EXPOSE 3000
VOLUME ["/app/data", "/app/pki"]

# Must start as root — entrypoint.sh creates the PUID/PGID user, fixes
# volume ownership, then execs node as that user itself.
USER root
ENTRYPOINT ["/entrypoint.sh"]
