FROM node:22-bookworm

RUN apt-get update && apt-get install -y \
    git \
    curl \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN npm install -g @anthropic-ai/claude-code @musistudio/claude-code-router@latest

WORKDIR /workspace

EXPOSE 3456
