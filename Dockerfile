# pull official base image
FROM python:3.11.4-slim-buster


# set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONUSERBASE=/vendor \
    PATH=/vendor/bin:$PATH


WORKDIR /vendor

# install system dependencies
RUN apt-get update && apt-get -y install libpq-dev gcc netcat

# install dependencies
RUN pip install --upgrade pip
RUN /bin/bash

# copy entrypoint.sh
COPY ./entrypoint.sh /vendor/entrypoint.sh
RUN sed -i 's/\r$//g' /vendor/entrypoint.sh
RUN chmod +x /vendor/entrypoint.sh

# copy project
COPY . /vendor/
RUN pip install -r requirements-dev.txt

# run entrypoint.sh
ENTRYPOINT ["/vendor/entrypoint.sh"]