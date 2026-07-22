FROM node:22-bookworm-slim AS build

ENV PNPM_HOME=/pnpm \
    SELF_HOSTED=1
ENV PATH=$PNPM_HOME:$PATH
WORKDIR /app

RUN corepack enable
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile

COPY app ./app
COPY build ./build
COPY db ./db
COPY drizzle ./drizzle
COPY public ./public
COPY worker ./worker
COPY .openai ./.openai
COPY next.config.ts postcss.config.mjs tsconfig.json vite.config.ts worker-configuration.d.ts ./
RUN pnpm run build

FROM node:22-bookworm-slim AS runtime

ENV NODE_ENV=production \
    PORT=3000 \
    HOST=0.0.0.0 \
    PNPM_HOME=/pnpm \
    PATH=/pnpm:$PATH
WORKDIR /app

RUN corepack enable

COPY --from=build --chown=node:node /app/package.json /app/pnpm-lock.yaml /app/pnpm-workspace.yaml ./
COPY --from=build --chown=node:node /app/node_modules ./node_modules
COPY --from=build --chown=node:node /app/dist ./dist

USER node
EXPOSE 3000
CMD ["node", "node_modules/vinext/dist/cli.js", "start", "--hostname", "0.0.0.0", "--port", "3000"]
