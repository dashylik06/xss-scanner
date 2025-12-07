from flask import Flask, render_template, request, jsonify
from scanner.xss_detector import XSSDetector
from scanner.url_scanner import URLScanner
import logging
import threading
from database import Database

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'

db = Database()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('xss_scanner.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/scan', methods=['GET', 'POST'])
def scan():
    if request.method == 'POST':
        url = request.form.get('url', '').strip()
        scan_type = request.form.get('scan_type', 'fast')

        if not url:
            return render_template('scan.html', error="Пожалуйста, введите URL")

        scan_id = str(hash(url + scan_type))
        db.create_scan(scan_id, url, scan_type)

        thread = threading.Thread(
            target=run_scan,
            args=(url, scan_type, scan_id)
        )
        thread.daemon = True
        thread.start()

        return render_template('scan.html', scan_id=scan_id, url=url)

    return render_template('scan.html')


@app.route('/scan_status/<scan_id>')
def get_scan_status(scan_id):
    status = db.get_scan_status(scan_id)
    return jsonify(status)


@app.route('/report/<scan_id>')
def report(scan_id):
    results = db.get_scan(scan_id)
    if results:
        security_level = results.get('scan_summary', {}).get('security_level', 'Безопасно').lower()
        if security_level == 'высокий риск':
            severity = 'high'
        elif security_level == 'средний риск':
            severity = 'medium'
        elif security_level == 'низкий риск':
            severity = 'low'
        else:
            severity = 'safe'

        recommendations = db.get_recommendations(severity)

        return render_template('report.html',
                               results=results,
                               scan_id=scan_id,
                               recommendations=recommendations)

    return render_template('report.html', error="Отчет не найден или сканирование еще не завершено")


@app.route('/history')
def history():
    scans = db.get_all_scans(limit=50)
    return render_template('history.html', scans=scans)


@app.route('/statistics')
def statistics():
    stats = db.get_statistics()
    return render_template('statistics.html', statistics=stats)


@app.route('/api/scan', methods=['POST'])
def api_scan():
    data = request.get_json()
    url = data.get('url', '').strip()
    scan_type = data.get('scan_type', 'fast')

    if not url:
        return jsonify({'error': 'URL обязателен'}), 400

    try:
        scanner = URLScanner()
        results = scanner.scan_url(url, scan_type)

        scan_id = str(hash(url + scan_type))
        db.create_scan(scan_id, url, scan_type)
        db.save_scan_results(scan_id, results)
        db.update_scan_status(scan_id, 'completed', 100, 'Сканирование завершено')

        return jsonify({'scan_id': scan_id, **results})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


def run_scan(url, scan_type, scan_id):
    try:
        logger.info(f"Начато сканирование URL: {url}")

        db.update_scan_status(scan_id, 'running', 25, 'Инициализация сканера...')

        scanner = URLScanner()

        db.update_scan_status(scan_id, 'running', 50, 'Сканирование на XSS...')

        results = scanner.scan_url(url, scan_type)

        db.save_scan_results(scan_id, results)
        db.update_scan_status(scan_id, 'completed', 100, 'Сканирование завершено')

        logger.info(f"Сканирование завершено для URL: {url}")

    except Exception as e:
        logger.error(f"Ошибка при сканировании: {str(e)}")
        db.update_scan_status(scan_id, 'error', 0, f'Ошибка: {str(e)}')


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)