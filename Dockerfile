FROM node:22-slim

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY core ./core

RUN mkdir -p /data && chown -R node:node /data /app

ENV NODE_ENV=production
USER node

EXPOSE 8443 8444

# Console on 8443 (published to host loopback by compose), forward-auth on 8444
# (reachable only from authz-net).
CMD ["node", "--disable-warning=ExperimentalWarning", "--experimental-sqlite", "core/cli.js", "serve", \
     "--host", "0.0.0.0", "--port", "8443", "--authz-host", "0.0.0.0", "--authz-port", "8444"]
