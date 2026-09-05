FROM node:22.23-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

FROM node:22.23-alpine
WORKDIR /app
ENV NODE_ENV=production
RUN apk add --no-cache docker-cli docker-cli-compose
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY --from=build /app/dist ./dist
EXPOSE 8085
CMD ["node", "dist/index.js"]
