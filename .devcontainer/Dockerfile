FROM mcr.microsoft.com/devcontainers/python:3.11

WORKDIR /workspace

COPY requirements.txt /tmp/requirements.txt
COPY requirements-dev.txt /tmp/requirements-dev.txt

RUN pip install --upgrade pip && \
    pip install -r /tmp/requirements.txt && \
    pip install -r /tmp/requirements-dev.txt && \
    rm /tmp/requirements.txt /tmp/requirements-dev.txt
