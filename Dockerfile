FROM node:20-alpine

WORKDIR /app

ENV NODE_ENV=production
ENV PORT=3000

# pg_dump / pg_restore / psql for the nightly backup job (src/backup). Match the server major if the
# repository has it, otherwise take the distribution default (it can still dump a 16 server).
RUN apk add --no-cache postgresql16-client || apk add --no-cache postgresql-client

COPY package*.json ./

RUN npm ci --omit=dev

COPY src ./src

USER node

EXPOSE 3000

CMD ["node", "src/server.js"]
