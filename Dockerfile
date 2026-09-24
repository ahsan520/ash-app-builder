FROM node:20-alpine

WORKDIR /app

ENV NODE_ENV=production
ENV PORT=3000

COPY package*.json ./

RUN npm ci --omit=dev

COPY src ./src

USER node

EXPOSE 3000

CMD ["node", "src/server.js"]
