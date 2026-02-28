FROM python:3.12-slim AS builder

WORKDIR /app

# Layer-cache: install dependencies before copying full source tree.
# pyproject.toml carries the dependency list; copying it first means the
# expensive pip-install layer is only rebuilt when dependencies change.
COPY pyproject.toml ./
RUN pip install --no-cache-dir .

# Now copy the rest of the source and install the project itself (fast,
# because dependencies are already cached in the layer above).
COPY . .
RUN pip install --no-cache-dir ".[dev]"

# --- runtime stage --------------------------------------------------------
FROM python:3.12-slim

LABEL maintainer="Mehrnoosh Abrishamchian"
LABEL version="0.1.0"
LABEL description="Na0S -- multi-layer prompt injection detector for LLM applications"

# Create a non-root user for security.
RUN groupadd --system na0s && useradd --system --gid na0s na0s

# Copy installed packages and the na0s entry-point from the builder stage.
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin/na0s /usr/local/bin/na0s

# Copy application source (needed for package data such as model .pkl files).
WORKDIR /app
COPY --from=builder /app /app

USER na0s

ENTRYPOINT ["na0s"]
CMD ["--help"]
