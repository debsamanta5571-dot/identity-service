#!/bin/sh
# Writes the runtime config the SPA loads at start-up (only the four variables listed are substituted).
set -eu
envsubst '${API_URL} ${CLIENT_ID} ${SCOPE}' < /etc/console/config.json.template > /usr/share/nginx/html/config.json
