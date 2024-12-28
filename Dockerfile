# Use the official Node.js image.
FROM node:16-alpine AS base

# Set the working directory
WORKDIR /app

# Copy package files and node_modules
COPY package*.json ./
COPY node_modules ./node_modules

# Expose the port
EXPOSE 5500

# Production stage
FROM base AS production
ENV NODE_ENV=production

# Copy the rest of the application
COPY . .

CMD ["node", "index.js"]

# Development stage
FROM base AS dev
ENV NODE_ENV=development

# Install nodemon globally
RUN npm install -g nodemon

# Copy the rest of the application
COPY . .

CMD ["npx", "nodemon", "index.js"]
