# Both stages use the same Python image, so the virtualenv built in the first
# stage runs unchanged in the second. Bump the Python and uv versions here.
ARG PYTHON_IMAGE=python:3.11.14-slim-bookworm
ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.9.30


FROM ${UV_IMAGE} AS uv


# Build stage: compiles the dependencies (psycopg2 builds from source) into
# /app/.venv. Its compilers and headers never reach the runtime image.
FROM ${PYTHON_IMAGE} AS build

COPY --from=uv /uv /bin/uv

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never

RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libc6-dev libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Cached unless pyproject.toml / uv.lock change
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-install-project


# Runtime stage
FROM ${PYTHON_IMAGE}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/app/.venv/bin:$PATH

# libpq5: psycopg2 at runtime. curl: Kamal's in-container /up healthcheck.
# postgresql-client: manage.py dbshell.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libpq5 curl postgresql-client \
    && rm -rf /var/lib/apt/lists/* \
    && addgroup --system django \
    && adduser --system --ingroup django django

WORKDIR /app

COPY --from=build /app/.venv /app/.venv
COPY --chmod=755 docker/* /

# The code stays owned by root: the app user can read it but not change it.
# local_blobs is the one writable directory, for DEFAULT_FILE_STORAGE_BACKEND=FileSystemStorage.
COPY . /app/
RUN python manage.py collectstatic --noinput \
    && install -d -o django -g django local_blobs

USER django

EXPOSE 8000

ENTRYPOINT ["/entrypoint"]
