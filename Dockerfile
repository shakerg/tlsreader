# Use the official Node.js image as the base image
FROM node:23-alpine 

# Set the working directory
WORKDIR /usr/src/app

# Copy package.json and package-lock.json
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy the rest of the application code
COPY . .

# Expose the port the app runs on
EXPOSE 3000

# Run the app as a non-root user
RUN chown -R node /usr/src/app/public
USER node

# Command to run the application
CMD ["node", "server.js"]