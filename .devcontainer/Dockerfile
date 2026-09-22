FROM mcr.microsoft.com/devcontainers/python:3.12-bookworm

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /usr/local/bin/

RUN curl --proto '=https' --tlsv1.2 -sSf https://just.systems/install.sh \
    | bash -s -- --to /usr/local/bin

USER vscode
RUN HOME=/home/vscode curl -fsSL https://opencode.ai/v2/install | bash

USER root
RUN ln -sf /home/vscode/.opencode/bin/opencode /usr/local/bin/opencode \
    && ln -sf /home/vscode/.opencode/bin/opencode2 /usr/local/bin/opencode2

ENV UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 \
    UV_PROJECT_ENVIRONMENT=/home/vscode/.venv
