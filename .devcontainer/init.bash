#!/bin/bash
set -x

sudo apt update && \
sudo apt install -y --no-install-recommends \
    ripgrep \
    vim-nox

# Install task runner
curl -1sLf 'https://dl.cloudsmith.io/public/task/task/setup.deb.sh' | sudo -E bash
sudo apt install -y task

# Install uv
curl -LsSf https://astral.sh/uv/install.sh | sh