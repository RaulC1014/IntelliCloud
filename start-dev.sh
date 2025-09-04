#!/bin/bash

echo "Starting Intellicloud Backend and Frontend..."

concurrently \
    "cd intellicloud-backend && .venv/Scripts/python.exe app.py" \
    "cd intellicloud-frontend && npm start"