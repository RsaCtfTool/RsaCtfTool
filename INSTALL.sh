#!/bin/bash

echo "[*] Creating virtual environment..."
python3 -m venv .env
source .env/bin/activate

echo "[*] Installing requirements.txt with pip3..."
pip3 install -r requirements.txt

echo "[+] Inserting wrapper alias into aliases file now..."
echo 'alias rsa-ctftool="$HOME/.local/share/RsaCtfTool/.env/bin/python $HOME/.local/share/RsaCtfTool/RsaCtfTool.py"' >> "$HOME/.config/zsh/aliases"

echo '[=] Done. Check by running $ rsa-ctf-tool after you resource your shell'
