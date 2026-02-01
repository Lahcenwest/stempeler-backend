FROM node:20-alpine

# Werkmap in de container
WORKDIR /app

# Package files kopiëren
COPY package*.json ./

# Dependencies installeren
RUN npm ci --omit=dev

# Alle code kopiëren
COPY . .

# Cloud Run gebruikt poort 8080
ENV PORT=8080
ENV NODE_ENV=production

EXPOSE 8080

# Start de server
CMD ["node", "index.js"]
