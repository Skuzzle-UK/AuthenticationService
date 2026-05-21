# Custom multi-stage Dockerfile for the local Backstage instance.
#
# Why we ship our own (rather than using Backstage's create-app default):
#
#   Backstage's default Dockerfile assumes you've already run `yarn install +
#   yarn build:backend` on the host -- it just packages the resulting tarballs.
#   That requires building three native modules locally (better-sqlite3,
#   isolated-vm, cpu-features) which on Windows needs Python 3 + Visual Studio
#   C++ Build Tools installed up front. Most dev boxes don't have that.
#
#   This Dockerfile does the whole build inside Linux containers instead. apt
#   gives us python3 + g++ + make, node-gyp happily compiles the native
#   modules, and the host only needs Node + Docker.
#
# Copied into the scaffolded local-backstage/ folder by
# scripts/setup-local-backstage.{ps1,sh} as packages/backend/Dockerfile,
# replacing the create-app default. The script then runs
# `docker image build . -f packages/backend/Dockerfile` from the scaffold root,
# so the rest of the workspace is available as build context.

# ============================================================================
# Stage 1: Build
# ============================================================================
# yarn install + tsc + build:backend inside a Linux container that has the
# native-build prereqs. Output is the standard packages/backend/dist/{skeleton,
# bundle}.tar.gz pair that Backstage's runtime stage consumes.
FROM node:22-bookworm-slim AS build

# Corporate-network workaround: disable strict TLS verification for the build
# stage only. Captured build logs from earlier runs showed every native module
# (better-sqlite3, keytar, isolated-vm, cpu-features) failing with
# "self-signed certificate in certificate chain" when node-gyp / prebuild-install
# tried to fetch node headers from https://nodejs.org/. That's the fingerprint
# of corporate SSL inspection (Zscaler / Netskope / etc.) re-signing HTTPS
# traffic with a private root CA the vanilla Debian trust store doesn't know
# about.
#
# Disabling verification here is safe because:
#   - Build-only — the runtime stage (where the app actually serves traffic)
#     does NOT inherit this; full TLS verification applies there.
#   - All HTTPS calls during build go to public artefact registries
#     (nodejs.org, registry.npmjs.org, github.com) the host already trusts.
#
# The "proper" fix is mounting the corporate root CA into the build stage
# (apt-installing it via /usr/local/share/ca-certificates/ + update-ca-certificates,
# plus pointing NODE_EXTRA_CA_CERTS at it). For a local-only dev tool we skip
# the CA-discovery dance.
ENV NODE_TLS_REJECT_UNAUTHORIZED=0
ENV npm_config_strict_ssl=false

# apt deps for native-module compilation. Backstage pulls in a surprising
# number of native bindings:
#   - better-sqlite3 needs python3 + g++ + libsqlite3-dev
#   - cpu-features needs cmake (not just make)
#   - isolated-vm needs python3 + g++ (compiles V8 isolates)
#   - keytar needs libsecret-1-dev (GNOME keyring API)
# Plus node-gyp itself expects to find `python` on PATH; on Debian where the
# binary is named `python3`, install python-is-python3 to symlink it.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 \
        python-is-python3 \
        g++ \
        make \
        cmake \
        build-essential \
        pkg-config \
        ca-certificates \
        git \
        libsqlite3-dev \
        libssl-dev \
        libsecret-1-dev && \
    rm -rf /var/lib/apt/lists/*

# corepack picks up the yarn version pinned in Backstage's package.json.
RUN corepack enable

# WORKDIR creates /app as the current user (root at this point). Yarn later
# wants to mkdir /app/node_modules as the `node` user, which fails with EACCES
# unless we chown the directory first. Doing this BEFORE `USER node` so the
# chown itself has permission.
WORKDIR /app
RUN chown -R node:node /app
USER node

# Copy the whole scaffolded workspace (which now also has our app-config.local.yaml
# in the root, courtesy of the setup script).
COPY --chown=node:node . .

# Plain `yarn install` (not --immutable) because:
#  - A fresh scaffold has no yarn.lock yet, so --immutable would reject the install
#  - The create-app templates ship a yarn.lock these days but Backstage may have
#    bumped versions since; --immutable would be too strict for a "build this
#    image on demand" flow.
#
# On failure we cat any node-gyp build logs to stdout so the real error
# (missing headers, wrong python, etc.) surfaces in the docker build output
# instead of being trapped inside the discarded container. yarn writes these
# under /tmp/xfs-*/build.log.
RUN yarn install || ( \
        echo '=== yarn install failed; dumping native-build logs ===' && \
        for log in /tmp/xfs-*/build.log; do \
            echo "--- $log ---"; \
            cat "$log" 2>/dev/null || true; \
        done && \
        exit 1 \
    )

# TypeScript compile + backend bundle. build:backend produces:
#   packages/backend/dist/skeleton.tar.gz   - workspace metadata for production install
#   packages/backend/dist/bundle.tar.gz     - the bundled backend code itself
RUN yarn tsc
RUN yarn build:backend

# ============================================================================
# Stage 2: Runtime
# ============================================================================
# Production image. Only runtime deps installed (libsqlite3-0 for better-sqlite3
# to load at runtime); dev deps + sources are left behind.
FROM node:22-bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        libsqlite3-0 \
        python3 \
        python3-pip && \
    rm -rf /var/lib/apt/lists/*

# TechDocs runs `mkdocs build` in-process when `techdocs.generator.runIn=local`
# (our setting). Without mkdocs + mkdocs-techdocs-core (the plugin Backstage's
# generator requires) installed in the runtime image, every Docs tab click
# fails with `spawn mkdocs ENOENT`.
#
# --break-system-packages: Debian 12's pip refuses system-wide install by
# default (PEP 668). Acceptable here because the container is single-purpose;
# we don't care about colliding with system Python packages.
RUN pip3 install --break-system-packages \
        mkdocs \
        mkdocs-techdocs-core \
        mkdocs-material

# Backstage's new frontend + backend systems behave very differently based on
# NODE_ENV. In `development`:
#   - Frontend auto-signs-in users via the configured guest provider (no
#     manual click on a sign-in button needed).
#   - Backend's permission + auth plugins relax strict policy enforcement.
#   - /api/auth/guest/refresh returns valid tokens instead of 403.
# Without this, the frontend's catalog calls all return 401 because the
# guest auth flow never completes -- the container's "production by default"
# mode treats anonymous requests as unauthenticated.
#
# Safe to set here because this container is local-dev only, bound to
# localhost. Production Backstage deployments build their own images with
# NODE_ENV=production and proper auth providers.
ENV NODE_ENV=development

RUN corepack enable

# Same /app-ownership fix as the build stage -- chown before switching user
# so yarn's later mkdir of /app/node_modules can succeed.
WORKDIR /app
RUN chown -R node:node /app
USER node

# Skeleton install: copy workspace metadata + yarn config, then production-only install.
#
# CRITICAL: .yarnrc.yml + .yarn/ must come along too. .yarnrc.yml carries
# `nodeLinker: node-modules` and `yarnPath: .yarn/releases/yarn-4.4.1.cjs`.
# Without it, Yarn 4 falls back to Plug'n'Play mode -- creates .pnp.cjs
# instead of node_modules/ -- and the compiled bundle then fails at runtime
# with "Cannot find module '@backstage/backend-defaults'" because there's no
# node_modules tree to resolve from. .yarn/releases/yarn-X.cjs is the
# bundled Yarn executable that yarnPath points at; without it corepack would
# download a different yarn version mid-build.
COPY --from=build --chown=node:node /app/.yarn ./.yarn
COPY --from=build --chown=node:node /app/.yarnrc.yml /app/yarn.lock /app/package.json /app/packages/backend/dist/skeleton.tar.gz ./
RUN tar xzf skeleton.tar.gz && rm skeleton.tar.gz

# Yarn's nodeLinker can be node-modules or pnp depending on Backstage's template
# defaults. Either way, `yarn workspaces focus --all --production` is the
# canonical "install only what runtime needs" command.
#
# No --mount=type=cache here: it makes Docker create /home/node/.cache as
# root-owned before USER node runs, which then breaks corepack's attempt to
# mkdir /home/node/.cache/node/corepack/v1 when downloading yarn. Drop the
# cache mount; node creates the dir itself with the right ownership.
#
# NODE_TLS_REJECT_UNAUTHORIZED inline (not via ENV) so it scopes ONLY to this
# RUN command -- the running container keeps full TLS verification. corepack's
# yarn download hits repo.yarnpkg.com which gets re-signed by the same
# corporate SSL inspector as during the build stage.
RUN NODE_TLS_REJECT_UNAUTHORIZED=0 \
    yarn workspaces focus --all --production && \
    rm -rf "$(yarn cache clean 2>/dev/null || echo /tmp/yarn-cache)"

# Bundled backend code + app-configs. Our overlay app-config.local.yaml is in
# the build stage's root (placed by the setup script), so the glob picks it up
# alongside the baseline app-config.yaml.
COPY --from=build --chown=node:node /app/packages/backend/dist/bundle.tar.gz /app/app-config*.yaml ./
RUN tar xzf bundle.tar.gz && rm bundle.tar.gz

# Backstage's backend listens on 7007 by default. The Aspire AppHost binds the
# matching host port.
EXPOSE 7007

# Load BOTH the baseline app-config.yaml AND our overlay app-config.local.yaml.
# create-app's default only loads app-config.yaml -- the *.local.yaml auto-load
# behaviour only kicks in for `yarn start` (Backstage's dev CLI), not for a
# packaged-and-run backend like ours. Without the explicit --config the
# overlay's catalog.locations and backend.auth flags never take effect.
# Order matters: later --config wins on key conflicts, so the overlay
# overrides the baseline correctly.
CMD ["node", "packages/backend", "--config", "app-config.yaml", "--config", "app-config.local.yaml"]
