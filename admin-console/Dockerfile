# Admin console. Build context: admin-console/
FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY . .
RUN npx ng build --configuration production

FROM nginxinc/nginx-unprivileged:1.29-alpine
USER root
# nginx.conf.template and config.json.template are filled from environment variables when the container starts,
# so one image serves any environment: API_URL, API_ORIGIN, CLIENT_ID, SCOPE.
COPY nginx.conf.template /etc/nginx/templates/default.conf.template
COPY config.json.template /etc/console/config.json.template
COPY 40-config.sh /docker-entrypoint.d/40-config.sh
COPY --from=build /app/dist/admin-console/browser /usr/share/nginx/html
RUN chmod +x /docker-entrypoint.d/40-config.sh && chown -R nginx:nginx /usr/share/nginx/html
USER nginx

ENV API_URL=http://localhost:5001 \
    API_ORIGIN=http://localhost:5001 \
    CLIENT_ID=admin-console \
    SCOPE="openid offline_access users:admin audit:read"
EXPOSE 8080
