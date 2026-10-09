# syntax=docker/dockerfile:1
# toSub2 源码随仓库提供（vendor/tosub2，审计过的固定提交），构建时不联网拉第三方代码。
FROM node:22.22.2-bookworm-slim AS node

FROM python:3.12.12-slim-bookworm
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/npm
RUN ln -s /usr/local/lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm
COPY requirements.txt /tmp/requirements.txt
RUN python -m pip install --no-cache-dir --only-binary=:all: -r /tmp/requirements.txt && rm /tmp/requirements.txt
COPY vendor/tosub2 /opt/tosub2
COPY runtime/package.json runtime/package-lock.json /opt/tosub2/
RUN cd /opt/tosub2 && npm ci --omit=dev --ignore-scripts --no-audit --no-fund \
    && rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /root/.npm
COPY server.mjs /app/server.mjs
RUN useradd --system --uid 10790 --home-dir /nonexistent relogin
USER relogin
ENV TOSUB2_ROOT=/opt/tosub2 TOSUB2_PYTHON=/usr/local/bin/python3 NODE_ENV=production
CMD ["node", "/app/server.mjs"]
