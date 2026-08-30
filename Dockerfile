FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

FROM node:22-alpine
WORKDIR /app
ENV NODE_ENV=production
# Docker CLI + compose plugin: used to provision per-project stacks through
# the host daemon (requires /var/run/docker.sock to be mounted).
RUN apk add --no-cache docker-cli docker-cli-compose
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY --from=build /app/dist ./dist
EXPOSE 8085
CMD ["node", "dist/index.js"]
