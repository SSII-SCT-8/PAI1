# Script de demostracion para Windows PowerShell
# Ejecuta el servidor y el cliente en ventanas separadas

Write-Host ""
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host " PAI1 - Sistema de Verificacion de Integridad" -ForegroundColor Cyan
Write-Host " Demo: Servidor + Cliente" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host ""

# Ruta base del proyecto
$BASE_DIR = Split-Path -Parent $PSScriptRoot

# Verificar que estamos en el directorio correcto
if (-not (Test-Path "$BASE_DIR\src")) {
    Write-Host "Error: No se encontro el directorio src/" -ForegroundColor Red
    Write-Host "Ejecute este script desde el directorio scripts/" -ForegroundColor Red
    exit 1
}

Write-Host "1. Limpiando base de datos anterior..." -ForegroundColor Yellow
$dbPath = Join-Path $BASE_DIR "data\server.db"
if (Test-Path $dbPath) {
    Remove-Item $dbPath -Force
    Write-Host "   OK Base de datos eliminada" -ForegroundColor Gray
}

Write-Host "2. Inicializando base de datos con usuarios de prueba..." -ForegroundColor Yellow
python "$BASE_DIR\config\seed_database.py"

Write-Host ""
Write-Host "3. Iniciando SERVIDOR en nueva ventana..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$BASE_DIR'; python -m src.server.server"

Write-Host ""
Write-Host "   Esperando 3 segundos para que el servidor inicie..." -ForegroundColor Gray
Start-Sleep -Seconds 3

Write-Host ""
Write-Host "4. Iniciando CLIENTE en nueva ventana..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$BASE_DIR'; python -m src.client.client"

Write-Host ""
Write-Host "======================================================================" -ForegroundColor Green
Write-Host " Demo iniciada exitosamente" -ForegroundColor Green
Write-Host "======================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "USUARIOS DE PRUEBA:" -ForegroundColor Cyan
Write-Host '  - Usuario: alice    | Password: AliceSecure2024!' -ForegroundColor White
Write-Host '  - Usuario: bob      | Password: BobPassword123#' -ForegroundColor White
Write-Host '  - Usuario: admin    | Password: AdminPass2024$' -ForegroundColor White
Write-Host ""
Write-Host "INSTRUCCIONES:" -ForegroundColor Cyan
Write-Host "  1. En la ventana del CLIENTE, use opcion 2 para hacer LOGIN" -ForegroundColor White
Write-Host "  2. Pruebe enviar transacciones (opcion 3)" -ForegroundColor White
Write-Host "  3. Pruebe los modos de ataque (opciones 5 y 6)" -ForegroundColor White
Write-Host ""
Write-Host "LOGS: Consulte el directorio logs/ para ver eventos del servidor y cliente" -ForegroundColor Cyan
Write-Host ""
Write-Host "Presione Ctrl+C en cada ventana para detener servidor/cliente" -ForegroundColor Gray
Write-Host ""
