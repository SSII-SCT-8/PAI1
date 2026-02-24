# Script para ejecutar SOLO el cliente
# Windows PowerShell

Write-Host ""
Write-Host "Iniciando cliente de integridad..." -ForegroundColor Yellow
Write-Host ""

$BASE_DIR = Split-Path -Parent $PSScriptRoot

# Verificar que existe el código del cliente
if (-not (Test-Path "$BASE_DIR\src\client\client.py")) {
    Write-Host "❌ Error: No se encontró src/client/client.py" -ForegroundColor Red
    exit 1
}

Write-Host "✓ Conectando al servidor en localhost:9999..." -ForegroundColor Green
Write-Host ""
Write-Host "USUARIOS DE PRUEBA:" -ForegroundColor Cyan
Write-Host "  - alice / AliceSecure2024!" -ForegroundColor White
Write-Host "  - bob / BobPassword123#" -ForegroundColor White
Write-Host "  - admin / AdminPass2024$" -ForegroundColor White
Write-Host ""
Write-Host "=" * 60 -ForegroundColor Gray

cd $BASE_DIR
python -m src.client.client
