FROM node:23-alpine 
LABEL org.opencontainers.image.source https://github.com/shakerg/tlsreader
WORKDIR /usr/src/app

COPY package*.json ./

RUN npm install

COPY . .

EXPOSE 3000

RUN chown -R node /usr/src/app/public
USER node

CMD ["node", "server.js"]
