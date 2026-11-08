# Kanuga Shield – Cloud Run Dockerfile
# Uses Node 20 slim for minimal attack surface

FROM node:20-slim

# Install system dependencies needed by better-sqlite3 (native module)
RUN apt-get update -y && apt-get install -y --no-install-recommends \
    python3 make g++ && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy package manifests first for layer caching
COPY package*.json ./

# Install production dependencies (rebuilds native modules for Linux)
RUN npm ci --omit=dev

# Copy application source
COPY . .

# Ensure the data directory exists for SQLite (ephemeral storage)
RUN mkdir -p data

# Cloud Run provides PORT via environment variable (default 8080)
ENV NODE_ENV=production
ENV PORT=8080

EXPOSE 8080

CMD ["node", "server.js"]
