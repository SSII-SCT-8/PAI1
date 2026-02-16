# Script para ejecutar SOLO el servidor en una nueva ventana
# Windows PowerShell

Write-Host ""
Write-Host "Iniciando servidor de integridad..." -ForegroundColor Yellow
Write-Host ""

$BASE_DIR = Split-Path -Parent $PSScriptRoot

# Verificar que existe el código del servidor
if (-not (Test-Path "$BASE_DIR\src\server\server.py")) {
    Write-Host "❌ Error: No se encontró src/server/server.py" -ForegroundColor Red
    exit 1
}

# Inicializar BD si no existe
if (-not (Test-Path "$BASE_DIR\data\server.db")) {
    Write-Host "Base de datos no encontrada. Inicializando..." -ForegroundColor Yellow
    python "$BASE_DIR\config\seed_database.py"
    Write-Host ""
}

# Iniciar servidor
Write-Host "✓ Iniciando servidor en puerto 9999..." -ForegroundColor Green
Write-Host ""
Write-Host "Para detener el servidor: Presione Ctrl+C" -ForegroundColor Cyan
Write-Host "Los logs se guardan en: logs/server.log" -ForegroundColor Cyan
Write-Host ""
Write-Host "=" * 60 -ForegroundColor Gray

cd $BASE_DIR
python -m src.server.server
