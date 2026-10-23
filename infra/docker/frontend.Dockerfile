FROM node:22-slim

RUN groupadd -g 10004 bayoraui && \
    useradd -u 10004 -g bayoraui -m -s /usr/sbin/nologin bayoraui

WORKDIR /app
COPY package.json /app/package.json
RUN npm install --omit=dev

COPY . /app
RUN chown -R 10004:10004 /app

USER 10004:10004
EXPOSE 3000
CMD ["npm", "run", "dev"]
