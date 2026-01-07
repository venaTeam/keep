FROM node:22-alpine

WORKDIR /app

RUN npm install -g mintlify

COPY . .

EXPOSE 3000

CMD ["mintlify", "dev", "--port", "3000", "--host", "0.0.0.0"]
