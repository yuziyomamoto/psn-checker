@echo off
chcp 65001 >nul
cd /d "%~dp0"


rem 1. Если есть готовый скомпилированный EXE
if exist "dist\psn_scanner.exe" (
    dist\psn_scanner.exe %*
    pause
    exit /b
)
if exist "psn_scanner.exe" (
    psn_scanner.exe %*
    pause
    exit /b
)

rem 2. Если в системе установлен Python
where python >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    python psn_scanner.py %*
    pause
    exit /b
)

rem 3. Автоматическая загрузка портативного Python (не требует прав админа и установки)
if not exist "python_embed\python.exe" (
    echo Python не найден в системе.
    echo Загрузка портативного Python (15 МБ, один раз)...
    powershell -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri 'https://www.python.org/ftp/python/3.11.8/python-3.11.8-embed-amd64.zip' -OutFile 'python_embed.zip'; Expand-Archive -Path 'python_embed.zip' -DestinationPath 'python_embed' -Force; Remove-Item 'python_embed.zip'"
    echo Установка зависимостей...
    powershell -Command "Invoke-WebRequest -Uri 'https://bootstrap.pypa.io/get-pip.py' -OutFile 'python_embed\get-pip.py'"
    python_embed\python.exe python_embed\get-pip.py --no-warn-script-location
    python_embed\python.exe -m pip install -r requirements.txt --no-warn-script-location
)

python_embed\python.exe psn_scanner.py %*
pause
