FROM node:22-bookworm-slim
LABEL org.opencontainers.image.source="https://github.com/shakerg/tlsreader"

# Ensure OpenSSL 3.x present, add tini for proper signal handling, then clean
RUN apt-get update \
	&& apt-get install -y --no-install-recommends openssl ca-certificates tini \
	&& rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/app

COPY package*.json ./
ENV NODE_ENV=production
RUN npm ci --omit=dev || npm install --production

COPY . .

EXPOSE 3000

RUN chown -R node:node /usr/src/app
USER node

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["node", "server.js"]
