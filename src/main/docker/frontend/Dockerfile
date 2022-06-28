FROM node:16 AS builder
WORKDIR /app


RUN npm  cache clear --force
 

RUN 
COPY ["package.json",".npmrc","/webpack/webpack.prod.js", "./"] .
COPY . .
RUN rm -rf ./target/*.jar
RUN npm config set strict-ssl false

RUN npm install && npm run webapp:build:prod


# Stage 1, based on Nginx, to have only the compiled app, ready for production with Nginx
FROM nginx:alpine
# Set working directory to nginx asset directory
WORKDIR /usr/share/nginx/html
# Remove default nginx static assets
RUN rm -rf ./*
# Copy static assets from builder stage
COPY --from=builder /app /usr/share/nginx/html
RUN rm /etc/nginx/conf.d/default.conf
COPY /src/main/docker/frontend/default.conf /etc/nginx/conf.d/
RUN rm -rf target
RUN rm -rf src
EXPOSE 9000
# Containers run nginx with global directives and daemon off
ENTRYPOINT ["nginx", "-g", "daemon off;"]