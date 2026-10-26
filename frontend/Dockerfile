# syntax=docker/dockerfile:1.7
FROM node:22-alpine AS build
WORKDIR /src
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY . .
RUN npm run build

FROM nginxinc/nginx-unprivileged:1.31-alpine AS runtime
USER root
# Pick up fixed Alpine packages that are newer than the base image snapshot (security patches).
RUN apk upgrade --no-cache
# Log directory must be writable by the unprivileged nginx user (a fresh named volume inherits these permissions).
RUN mkdir -p /var/log/nginx && rm -f /var/log/nginx/*.log && chown -R 101:0 /var/log/nginx && chmod 775 /var/log/nginx
USER 101
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /src/dist /usr/share/nginx/html
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --retries=5 CMD wget -qO- http://127.0.0.1:8080/nginx-health || exit 1
