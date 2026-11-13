FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY model ./model
COPY script ./script
COPY backend/containerbrowser ./backend/containerbrowser
COPY cmd/mechanize-browser-mcp ./cmd/mechanize-browser-mcp
RUN CGO_ENABLED=0 go build -trimpath -o /out/mechanize-browser-mcp ./cmd/mechanize-browser-mcp

FROM node:24-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends tini ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app/browser
COPY browser/playwright/package.json browser/playwright/package-lock.json ./
RUN npm ci --omit=dev && npx playwright-core install --with-deps chromium
COPY browser/playwright/sessions.mjs browser/playwright/container-worker.mjs browser/playwright/container-executor.mjs ./
COPY --from=build /out/mechanize-browser-mcp /usr/local/bin/mechanize-browser-mcp
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/browsers
RUN mv /root/.cache/ms-playwright /opt/browsers && chmod -R a+rX /opt/browsers
USER node
EXPOSE 8080
ENTRYPOINT ["/usr/bin/tini", "--", "mechanize-browser-mcp"]
CMD ["-config", "/run/secrets/browser-config.json"]
