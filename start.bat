@echo off
chcp 65001
title XSS Scanner
echo ========================================
echo    Запуск XSS Scanner
echo ========================================
echo.

cd /d "C:\Users\PC\XSS_Protection_System\xss"

echo Проверяю виртуальное окружение...
if not exist ".venv\Scripts\activate.bat" (
    echo Создаю виртуальное окружение...
    python -m venv .venv
)

echo Активирую виртуальное окружение...
call .venv\Scripts\activate.bat

echo Проверяю зависимости...
python -c "import flask" >nul 2>&1
if errorlevel 1 (
    echo Устанавливаю зависимости из requirements.txt...
    pip install -r requirements.txt
)

echo Запускаю приложение...
echo Откройте браузер: http://localhost:5000
echo.
python app.py

pause