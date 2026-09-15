$ErrorActionPreference = "Stop"

Push-Location $PSScriptRoot
try {
    # Named gateway state is preserved. Use `docker compose down -v` only when
    # you intentionally want to erase approvals, audit events, and manifest state.
    docker compose down
} finally {
    Pop-Location
}
