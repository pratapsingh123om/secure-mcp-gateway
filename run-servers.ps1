$ErrorActionPreference = "Stop"

# Activate python environment
. .\venv\Scripts\Activate.ps1

Write-Host "Starting CRM Synthetic Server..."
Start-Process "uvicorn" -ArgumentList "synthetic-servers.crm:app", "--port", "8001" -NoNewWindow

Write-Host "Starting HR Synthetic Server..."
Start-Process "uvicorn" -ArgumentList "synthetic-servers.hr:app", "--port", "8002" -NoNewWindow

Write-Host "Starting Gateway..."
Start-Process "uvicorn" -ArgumentList "backend.main:app", "--port", "8000" -NoNewWindow

Write-Host "All servers started!"
