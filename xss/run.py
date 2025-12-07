import os
import sys
import subprocess


def main():
    print("=" * 50)
    print("🚀 Запуск XSS Scanner")
    print("=" * 50)


    if not os.path.exists('venv'):
        print("📦 Создаю виртуальное окружение...")
        result = subprocess.run([sys.executable, '-m', 'venv', 'venv'],
                                capture_output=True, text=True)
        if result.returncode != 0:
            print("❌ Ошибка при создании виртуального окружения:")
            print(result.stderr)
            return


    if os.name == 'nt':  # Windows
        python_exe = os.path.join('venv', 'Scripts', 'python.exe')
        pip_exe = os.path.join('venv', 'Scripts', 'pip.exe')
    else:  # Linux/Mac
        python_exe = os.path.join('venv', 'bin', 'python')
        pip_exe = os.path.join('venv', 'bin', 'pip')


    requirements_installed = True
    try:
        subprocess.run([python_exe, '-c', 'import flask, requests, bs4'],
                       capture_output=True, check=True)
    except:
        requirements_installed = False

    if not requirements_installed:
        print("📥 Устанавливаю зависимости...")
        result = subprocess.run([pip_exe, 'install', '-r', 'requirements.txt'],
                                capture_output=True, text=True)
        if result.returncode != 0:
            print("❌ Ошибка при установке зависимостей:")
            print(result.stderr)
            return
        print("✅ Зависимости установлены успешно!")


    print("🌐 Запускаю веб-приложение...")
    print("📍 Откройте браузер и перейдите по адресу: http://localhost:5000")
    print("⏹️  Для остановки нажмите Ctrl+C")
    print("=" * 50)

    try:
        subprocess.run([python_exe, 'app.py'])
    except KeyboardInterrupt:
        print("\n👋 Приложение остановлено")
    except Exception as e:
        print(f"❌ Ошибка при запуске: {e}")


if __name__ == '__main__':
    main()