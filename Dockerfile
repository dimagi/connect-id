# pull official base image
FROM python:3.11.4-slim-bookworm


# set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONUSERBASE=/app \
    PATH=/app/bin:$PATH


WORKDIR /app

# install system dependencies
RUN apt-get update && apt-get -y install libpq-dev gcc curl


RUN addgroup --system django \
    && adduser --system --ingroup django django

# install dependencies
RUN pip install --upgrade pip
RUN /bin/bash

# copy project
COPY --chown=django:django . /app/
RUN pip install -r requirements.txt

COPY ./docker/* /
RUN chmod +x /entrypoint /start*
RUN chown django /entrypoint /start*
RUN python /app/manage.py collectstatic --noinput
RUN chown django:django -R staticfiles

USER django

EXPOSE 8000

ENTRYPOINT ["/entrypoint"]
