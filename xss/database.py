import sqlite3
import logging
from contextlib import contextmanager
from datetime import datetime

logger = logging.getLogger(__name__)


class Database:
    def __init__(self, db_path='xss_scanner.db'):
        self.db_path = db_path
        self.init_db()
        self.seed_recommendations()

    @contextmanager
    def get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            logger.error(f"Database error: {str(e)}")
            raise
        finally:
            conn.close()

    def init_db(self):
        with self.get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT UNIQUE NOT NULL,
                    url TEXT NOT NULL,
                    scan_type TEXT NOT NULL,
                    status TEXT DEFAULT 'pending',
                    progress INTEGER DEFAULT 0,
                    message TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    completed_at DATETIME
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    vuln_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    description TEXT,
                    location TEXT,
                    evidence TEXT,
                    risk_score INTEGER,
                    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scan_summaries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT UNIQUE NOT NULL,
                    total_vulnerabilities INTEGER DEFAULT 0,
                    high_risk INTEGER DEFAULT 0,
                    medium_risk INTEGER DEFAULT 0,
                    low_risk INTEGER DEFAULT 0,
                    total_risk_score INTEGER DEFAULT 0,
                    security_level TEXT,
                    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS recommendations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    priority INTEGER DEFAULT 0
                )
            ''')

            cursor.execute('CREATE INDEX IF NOT EXISTS idx_scans_scan_id ON scans(scan_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_vulns_scan_id ON vulnerabilities(scan_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity)')

    def seed_recommendations(self):
        recommendations = [
            ('high', 'Немедленная блокировка',
             'Немедленно заблокируйте атакующий IP-адрес и проверьте журналы сервера.', 1),
            ('high', 'Экранирование вывода',
             'Используйте функции экранирования для всех пользовательских данных.', 2),
            ('high', 'Content Security Policy',
             'Настройте заголовок Content-Security-Policy.', 3),
            ('medium', 'Валидация входных данных',
             'Реализуйте строгую валидацию всех параметров.', 1),
            ('medium', 'Обновление библиотек',
             'Обновите фреймворки до последних версий.', 2),
            ('medium', 'Проверка конфигурации',
             'Проверьте настройки веб-сервера.', 3),
            ('low', 'Регулярное сканирование',
             'Настройте регулярное автоматическое сканирование.', 1),
            ('low', 'Мониторинг логов',
             'Внедрите систему мониторинга логов.', 2),
            ('low', 'Обучение разработчиков',
             'Проведите обучение по безопасному программированию.', 3),
            ('safe', 'Проактивный мониторинг',
             'Продолжайте регулярный мониторинг.', 1),
            ('safe', 'Пентестинг',
             'Проводите регулярное тестирование на проникновение.', 2),
            ('safe', 'Резервное копирование',
             'Обеспечьте регулярное резервное копирование.', 3),
        ]

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM recommendations')
            if cursor.fetchone()[0] == 0:
                cursor.executemany('''
                    INSERT INTO recommendations (severity, title, description, priority)
                    VALUES (?, ?, ?, ?)
                ''', recommendations)

    def create_scan(self, scan_id, url, scan_type):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO scans (scan_id, url, scan_type, status, progress, message)
                VALUES (?, ?, ?, 'pending', 0, 'Инициализация...')
            ''', (scan_id, url, scan_type))
            return scan_id

    def update_scan_status(self, scan_id, status, progress=0, message=''):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            if status == 'completed':
                cursor.execute('''
                    UPDATE scans 
                    SET status = ?, progress = ?, message = ?, completed_at = CURRENT_TIMESTAMP
                    WHERE scan_id = ?
                ''', (status, progress, message, scan_id))
            else:
                cursor.execute('''
                    UPDATE scans 
                    SET status = ?, progress = ?, message = ?
                    WHERE scan_id = ?
                ''', (status, progress, message, scan_id))

    def save_scan_results(self, scan_id, results):
        with self.get_connection() as conn:
            cursor = conn.cursor()

            vulnerabilities = results.get('vulnerabilities', [])
            for vuln in vulnerabilities:
                cursor.execute('''
                    INSERT INTO vulnerabilities 
                    (scan_id, vuln_type, severity, description, location, evidence, risk_score)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    scan_id,
                    vuln.get('type', 'unknown'),
                    vuln.get('severity', 'medium'),
                    vuln.get('description', ''),
                    vuln.get('location', ''),
                    str(vuln.get('evidence', [])[:3]),
                    vuln.get('risk_score', 0)
                ))

            summary = results.get('scan_summary', {})
            cursor.execute('''
                INSERT INTO scan_summaries 
                (scan_id, total_vulnerabilities, high_risk, medium_risk, low_risk, 
                 total_risk_score, security_level)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                scan_id,
                summary.get('total_vulnerabilities', 0),
                summary.get('high_risk', 0),
                summary.get('medium_risk', 0),
                summary.get('low_risk', 0),
                summary.get('total_risk_score', 0),
                summary.get('security_level', 'Безопасно')
            ))

    def get_scan(self, scan_id):
        with self.get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute('SELECT * FROM scans WHERE scan_id = ?', (scan_id,))
            scan_data = cursor.fetchone()
            if not scan_data:
                return None

            cursor.execute('SELECT * FROM vulnerabilities WHERE scan_id = ?', (scan_id,))
            vulnerabilities = []
            for row in cursor.fetchall():
                vuln = dict(row)
                if vuln['evidence']:
                    vuln['evidence'] = eval(vuln['evidence'])
                else:
                    vuln['evidence'] = []
                vulnerabilities.append(vuln)

            cursor.execute('SELECT * FROM scan_summaries WHERE scan_id = ?', (scan_id,))
            summary_row = cursor.fetchone()
            summary = dict(summary_row) if summary_row else {}

            result = {
                'scan_id': scan_id,
                'url': scan_data['url'],
                'scan_type': scan_data['scan_type'],
                'timestamp': scan_data['timestamp'],
                'vulnerabilities': vulnerabilities,
                'scan_summary': summary
            }

            return result

    def get_scan_status(self, scan_id):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT status, progress, message FROM scans 
                WHERE scan_id = ?
            ''', (scan_id,))
            row = cursor.fetchone()
            if row:
                return dict(row)
            return {'status': 'not_found'}

    def get_recommendations(self, severity):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT title, description, priority 
                FROM recommendations 
                WHERE severity = ? 
                ORDER BY priority
                LIMIT 3
            ''', (severity,))
            return [dict(row) for row in cursor.fetchall()]

    def get_all_scans(self, limit=50):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT s.*, ss.security_level, ss.total_vulnerabilities
                FROM scans s
                LEFT JOIN scan_summaries ss ON s.scan_id = ss.scan_id
                ORDER BY s.timestamp DESC
                LIMIT ?
            ''', (limit,))
            return [dict(row) for row in cursor.fetchall()]

    def get_statistics(self):
        with self.get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute('''
                SELECT 
                    COUNT(*) as total_scans,
                    SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed_scans,
                    SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END) as running_scans,
                    SUM(CASE WHEN status = 'error' THEN 1 ELSE 0 END) as error_scans
                FROM scans
            ''')
            stats = dict(cursor.fetchone())

            cursor.execute('''
                SELECT 
                    severity,
                    COUNT(*) as count
                FROM vulnerabilities
                GROUP BY severity
            ''')
            severity_stats = {row['severity']: row['count'] for row in cursor.fetchall()}

            stats['vulnerabilities_by_severity'] = severity_stats
            return stats