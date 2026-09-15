$ErrorActionPreference = "Stop"

Push-Location $PSScriptRoot
try {
    docker compose up -d --build

    $ready = $false
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        try {
            $response = Invoke-WebRequest -Uri "http://127.0.0.1:8000/ready" -TimeoutSec 2 -SkipHttpErrorCheck
            if ($response.StatusCode -eq 200) {
                $ready = $true
                break
            }
        } catch {
            # Services are still starting.
        }
        Start-Sleep -Seconds 1
    }

    if (-not $ready) {
        docker compose logs --no-color gateway opa crm hr billing
        throw "Gateway did not become ready within 60 seconds."
    }

    Write-Host "Gateway ready:  http://127.0.0.1:8000/ready"
    Write-Host "MCP endpoint:   http://127.0.0.1:8000/mcp"
    Write-Host "Dashboard:      http://127.0.0.1:5173"
} finally {
    Pop-Location
}
