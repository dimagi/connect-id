# pull official base image (includes uv)
FROM ghcr.io/astral-sh/uv:python3.11-bookworm-slim


# set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    PATH=/app/.venv/bin:$PATH


WORKDIR /app

# install system dependencies
RUN apt-get update && apt-get -y install libpq-dev gcc curl


RUN addgroup --system django \
    && adduser --system --ingroup django django

# install dependencies (cached unless pyproject.toml / uv.lock change)
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

# copy project
COPY --chown=django:django . /app/

COPY ./docker/* /
RUN chmod +x /entrypoint /start*
RUN chown django /entrypoint /start*
RUN python /app/manage.py collectstatic --noinput
RUN chown django:django -R staticfiles

RUN mkdir -p /var/run/celery && chown django:django /var/run/celery

USER django

EXPOSE 8000

ENTRYPOINT ["/entrypoint"]
