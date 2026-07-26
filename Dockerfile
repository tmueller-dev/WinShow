# syntax=docker/dockerfile:1
#
# WinShow MCP server.
#
# Two stages: the first builds a virtual environment, the second carries only that
# environment and the interpreter. Deployment guidance is in docs/DEPLOYMENT.md and the
# reasoning behind the runtime shape is in docs/07-operations.md §1.

# --------------------------------------------------------------------------- builder

FROM python:3.12-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /build

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy only what the build backend needs to resolve dependencies first, so a source-only
# change does not invalidate the dependency layer.
COPY pyproject.toml README.md LICENSE ./
COPY src ./src

RUN pip install --upgrade pip setuptools wheel \
 && pip install .

# --------------------------------------------------------------------------- runtime

FROM python:3.12-slim AS runtime

LABEL org.opencontainers.image.title="WinShow" \
      org.opencontainers.image.description="MCP server brokering a Windows host that dials out" \
      org.opencontainers.image.source="https://github.com/tmueller-dev/WinShow" \
      org.opencontainers.image.documentation="https://github.com/tmueller-dev/WinShow/tree/main/docs" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later"

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    WINSHOW_HOST=0.0.0.0 \
    WINSHOW_PORT=8080

# The venv is copied whole, including every dependency's .dist-info directory.
# THIRD-PARTY-NOTICES.md promises those licence texts remain present in the published
# image, and the MIT, BSD and Apache-2.0 terms require it of a redistributor. Do not add
# a "slimming" step that deletes them.
COPY --from=builder /opt/venv /opt/venv

# An unprivileged account with no shell and no home to write to. The server needs no
# filesystem access of its own: its only durable state is the audit log, and that is
# either stdout or an explicitly mounted volume.
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin winshow
USER 10001:10001

# 8080 is the public listener carrying /mcp and /agent; 9090 is the admin listener
# carrying /metrics, which must never be routed to the public interface.
EXPOSE 8080 9090

# Liveness, not readiness. /readyz goes red whenever the Windows host is away, and
# restarting this container because a remote machine rebooted would be exactly wrong
# (docs/07-operations.md §1.1). Written with urllib so the image needs no curl.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2).status == 200 else 1)"]

# Exactly one worker, always. The agent holds a single WebSocket; with two workers that
# socket lands in one of them while an MCP request may arrive in the other, where the
# bridge has no agent to route to. Scaling out needs an agent-affinity layer, not more
# workers (docs/02-architecture.md §2.1).
ENTRYPOINT ["winshow"]
