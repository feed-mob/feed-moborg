FROM node:24-slim AS build

WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY tsconfig.json ./
COPY http.ts ./
COPY scripts ./scripts
COPY scraped ./scraped
RUN npm run build

FROM node:24-slim AS runtime

WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev

COPY --from=build /app/dist ./dist
COPY data/db/docs.sqlite ./data/db/docs.sqlite

ENV NODE_ENV=production
ENV AUTH_MODE=none
ENV HOST=0.0.0.0
ENV PORT=3000

EXPOSE 3000

CMD ["node", "--experimental-sqlite", "dist/http.js"]
