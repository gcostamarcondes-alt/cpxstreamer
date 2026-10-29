@echo off
chcp 65001 >nul
cd /d "%~dp0"
where node >nul 2>&1
if errorlevel 1 (
  echo ERRO: Instale o Node.js 22 ou superior em https://nodejs.org/
  pause
  exit /b 1
)
for /f %%v in ('node -p "process.versions.node.split('.')[0]"') do set MAJOR=%%v
if %MAJOR% LSS 22 (
  echo ERRO: Para o portal funcionar, use Node.js 22 ou mais recente.
  pause
  exit /b 1
)
echo Iniciando Complexo RP - Portal de Streamers...
start "COMPLEXO RP - SERVIDOR" cmd /k "node server.js"
timeout /t 3 /nobreak >nul
start "" "http://127.0.0.1:3045"
echo Site aberto! Mantenha a janela COMPLEXO RP - SERVIDOR aberta.
echo Para mostrar lives automaticamente, configure as APIs no arquivo .env.
echo Para TikTok ou sem API, marque AO VIVO manualmente no painel.
pause
