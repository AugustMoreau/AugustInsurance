# =============================================================================
# AUGUSTIUM INSURANCE BACKEND DOCKERFILE
# =============================================================================
# Multi-stage build for optimized production image

# =============================================================================
# Stage 1: Build Stage
# =============================================================================
FROM node:18-alpine AS builder

# Set working directory
WORKDIR /app

# Install build dependencies
RUN apk add --no-cache \
    python3 \
    make \
    g++ \
    git

# Copy package files
COPY package*.json ./
COPY tsconfig.json ./

# Install dependencies
RUN npm ci --only=production --silent

# Copy source code
COPY src/ ./src/

# Build the application
RUN npm run build

# =============================================================================
# Stage 2: Production Stage
# =============================================================================
FROM node:18-alpine AS production

# Set environment variables
ENV NODE_ENV=production
ENV PORT=3000
ENV USER=augustium
ENV GROUP=augustium
ENV UID=1001
ENV GID=1001

# Install runtime dependencies
RUN apk add --no-cache \
    dumb-init \
    curl \
    ca-certificates \
    && update-ca-certificates

# Create non-root user
RUN addgroup -g $GID $GROUP \
    && adduser -D -u $UID -G $GROUP -s /bin/sh $USER

# Set working directory
WORKDIR /app

# Change ownership of the app directory
RUN chown -R $USER:$GROUP /app

# Switch to non-root user
USER $USER

# Copy package files
COPY --chown=$USER:$GROUP package*.json ./

# Install production dependencies only
RUN npm ci --only=production --silent && npm cache clean --force

# Copy built application from builder stage
COPY --from=builder --chown=$USER:$GROUP /app/dist ./dist

# Copy additional files
COPY --chown=$USER:$GROUP .env.example ./.env.example

# Create necessary directories
RUN mkdir -p logs uploads temp

# Expose port
EXPOSE $PORT

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:$PORT/health || exit 1

# Use dumb-init to handle signals properly
ENTRYPOINT ["dumb-init", "--"]

# Start the application
CMD ["node", "dist/server.js"]

# =============================================================================
# Stage 3: Development Stage
# =============================================================================
FROM node:18-alpine AS development

# Set environment variables
ENV NODE_ENV=development
ENV PORT=3000

# Install development dependencies
RUN apk add --no-cache \
    python3 \
    make \
    g++ \
    git \
    curl

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./
COPY tsconfig.json ./

# Install all dependencies (including dev dependencies)
RUN npm install

# Copy source code
COPY . .

# Create necessary directories
RUN mkdir -p logs uploads temp

# Expose port
EXPOSE $PORT

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:$PORT/health || exit 1

# Start development server
CMD ["npm", "run", "dev"]

# =============================================================================
# Labels
# =============================================================================
LABEL maintainer="Augustium Insurance Team <dev@augustium-insurance.com>"
LABEL version="1.0.0"
LABEL description="Augustium Health Insurance Claims Processing Backend"
LABEL org.opencontainers.image.title="Augustium Insurance Backend"
LABEL org.opencontainers.image.description="Professional-grade blockchain-based insurance claims system"
LABEL org.opencontainers.image.version="1.0.0"
LABEL org.opencontainers.image.vendor="Augustium Insurance"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.source="https://github.com/augustium/insurance-claims-backend"
LABEL org.opencontainers.image.documentation="https://github.com/augustium/insurance-claims-backend/blob/main/README.md"