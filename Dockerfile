FROM node:24-slim AS build

WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY tsconfig.json ./
COPY http.ts ./
COPY scripts ./scripts
RUN npm run build

FROM node:24-slim AS runtime

WORKDIR /app

RUN apt-get update \
  && apt-get install -y --no-install-recommends curl \
  && rm -rf /var/lib/apt/lists/*

COPY package*.json ./
RUN npm ci --omit=dev

COPY --from=build /app/dist ./dist
COPY data/db/docs.sqlite ./data/db/docs.sqlite

ENV NODE_ENV=production
ENV AUTH_MODE=none
ENV HOST=0.0.0.0
ENV PORT=3000
ENV BASE_URL=
ENV ALLOWED_DOMAIN=
ENV GOOGLE_CLIENT_ID=
ENV GOOGLE_CLIENT_SECRET=
# Secret used to sign issued MCP access tokens (HS256). Set a stable random value
# in Coolify so tokens survive redeploys; if empty, a random one is generated per
# boot (clients simply re-authenticate after a restart).
ENV TOKEN_SECRET=

EXPOSE 3000

CMD ["node", "--experimental-sqlite", "dist/http.js"]
