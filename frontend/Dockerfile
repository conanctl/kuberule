FROM node:22-alpine

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .

ENV NEXT_PUBLIC_API_BASE=http://localhost:18081
EXPOSE 3000

CMD ["npm", "run", "dev"]
