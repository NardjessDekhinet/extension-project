# Base image
FROM node:18
# Set working directory
WORKDIR /app
# Copy dependencies
COPY package*.json ./
# Install dependencies
RUN npm install
# Copy backend code
COPY . .
# Expose port
EXPOSE 3000
# Run server
CMD ["node", "server.js"]
