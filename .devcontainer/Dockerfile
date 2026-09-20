FROM node:20-bookworm

RUN apt-get update && apt-get install -y \
    git \
    curl \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN npm install -g @anthropic-ai/claude-code @musistudio/claude-code-router

WORKDIR /workspace

EXPOSE 3456
