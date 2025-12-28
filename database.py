import sqlite3
import json
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
        """Контекстный менеджер для соединения с БД"""
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
        """Инициализация таблиц базы данных"""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Таблица сканирований
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

            # Таблица уязвимостей
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                vuln_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT,
                location TEXT,
                evidence TEXT,  -- Будем хранить как JSON
                risk_score INTEGER,
                FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
            )
            ''')

            # Таблица сводок сканирования
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

            # Таблица рекомендаций
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS recommendations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                priority INTEGER DEFAULT 0
            )
            ''')

            # Индексы для ускорения запросов
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_scans_scan_id ON scans(scan_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_vulns_scan_id ON vulnerabilities(scan_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_recs_severity ON recommendations(severity)')

    def seed_recommendations(self):
        """Заполнение таблицы рекомендаций начальными данными"""
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
            count = cursor.fetchone()[0]

            if count == 0:
                cursor.executemany('''
                INSERT INTO recommendations (severity, title, description, priority)
                VALUES (?, ?, ?, ?)
                ''', recommendations)
                logger.info(f"Добавлено {len(recommendations)} рекомендаций")

    def create_scan(self, scan_id, url, scan_type):
        """Создание новой записи сканирования"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
            INSERT INTO scans (scan_id, url, scan_type, status, progress, message)
            VALUES (?, ?, ?, 'pending', 0, 'Инициализация...')
            ''', (scan_id, url, scan_type))
            logger.debug(f"Создано сканирование {scan_id}")
            return scan_id

    def update_scan_status(self, scan_id, status, progress=0, message=''):
        """Обновление статуса сканирования"""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            update_params = [status, progress, message, scan_id]

            if status == 'completed':
                query = '''
                UPDATE scans 
                SET status = ?, progress = ?, message = ?, completed_at = CURRENT_TIMESTAMP
                WHERE scan_id = ?
                '''
            else:
                query = '''
                UPDATE scans 
                SET status = ?, progress = ?, message = ?
                WHERE scan_id = ?
                '''

            cursor.execute(query, update_params)
            logger.debug(f"Обновлен статус {scan_id}: {status} ({progress}%)")

    def save_scan_results(self, scan_id, results):
        """Сохранение результатов сканирования"""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Сохранение уязвимостей
            vulnerabilities = results.get('vulnerabilities', [])
            for vuln in vulnerabilities:
                # Безопасное сохранение evidence как JSON
                evidence = vuln.get('evidence', [])
                if isinstance(evidence, list):
                    evidence_json = json.dumps(evidence[:3])  # Ограничиваем 3 элемента
                else:
                    evidence_json = json.dumps([])

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
                    evidence_json,
                    vuln.get('risk_score', 0)
                ))

            # Сохранение сводки
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

            logger.info(f"Сохранены результаты сканирования {scan_id}: {len(vulnerabilities)} уязвимостей")

    def get_scan(self, scan_id):
        """Получение полных данных сканирования"""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Основные данные сканирования
            cursor.execute('SELECT * FROM scans WHERE scan_id = ?', (scan_id,))
            scan_data = cursor.fetchone()

            if not scan_data:
                return None

            # Уязвимости
            cursor.execute('SELECT * FROM vulnerabilities WHERE scan_id = ?', (scan_id,))
            vulnerabilities = []
            for row in cursor.fetchall():
                vuln = dict(row)
                # Безопасное чтение JSON (замена eval)
                evidence_str = vuln.get('evidence', '[]')
                try:
                    vuln['evidence'] = json.loads(evidence_str)
                except (json.JSONDecodeError, TypeError):
                    vuln['evidence'] = []
                vulnerabilities.append(vuln)

            # Сводка
            cursor.execute('SELECT * FROM scan_summaries WHERE scan_id = ?', (scan_id,))
            summary_row = cursor.fetchone()
            summary = dict(summary_row) if summary_row else {}

            # Формирование результата
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
        """Получение текущего статуса сканирования"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
            SELECT status, progress, message FROM scans
            WHERE scan_id = ?
            ''', (scan_id,))

            row = cursor.fetchone()
            if row:
                return {
                    'status': row['status'],
                    'progress': row['progress'],
                    'message': row['message']
                }
            return {'status': 'not_found', 'progress': 0, 'message': 'Сканирование не найдено'}

    def get_recommendations(self, severity):
        """Получение рекомендаций по уровню серьезности"""
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
        """Получение списка всех сканирований"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
            SELECT s.*, ss.security_level, ss.total_vulnerabilities
            FROM scans s
            LEFT JOIN scan_summaries ss ON s.scan_id = ss.scan_id
            ORDER BY s.timestamp DESC
            LIMIT ?
            ''', (limit,))

            scans = []
            for row in cursor.fetchall():
                scan = dict(row)
                # Очистка длинных URL для отображения
                if len(scan['url']) > 50:
                    scan['url_display'] = scan['url'][:47] + '...'
                else:
                    scan['url_display'] = scan['url']
                scans.append(scan)

            return scans

    def get_statistics(self):
        """Получение статистики по всем сканированиям"""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Основная статистика
            cursor.execute('''
            SELECT
                COUNT(*) as total_scans,
                SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed_scans,
                SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END) as running_scans,
                SUM(CASE WHEN status = 'error' THEN 1 ELSE 0 END) as error_scans,
                AVG(progress) as avg_progress
            FROM scans
            ''')

            stats = dict(cursor.fetchone())

            # Статистика по уязвимостям
            cursor.execute('''
            SELECT
                severity,
                COUNT(*) as count
            FROM vulnerabilities
            GROUP BY severity
            ''')

            severity_stats = {row['severity']: row['count'] for row in cursor.fetchall()}
            stats['vulnerabilities_by_severity'] = severity_stats

            # Статистика по типам сканирования
            cursor.execute('''
            SELECT
                scan_type,
                COUNT(*) as count
            FROM scans
            WHERE status = 'completed'
            GROUP BY scan_type
            ''')

            scan_type_stats = {row['scan_type']: row['count'] for row in cursor.fetchall()}
            stats['scans_by_type'] = scan_type_stats

            return stats

    def delete_scan(self, scan_id):
        """Удаление сканирования и связанных данных"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM scans WHERE scan_id = ?', (scan_id,))
            logger.info(f"Удалено сканирование {scan_id}")
            return cursor.rowcount > 0

    def cleanup_old_scans(self, days_old=30):
        """Очистка старых записей"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
            DELETE FROM scans 
            WHERE timestamp < datetime('now', ?)
            ''', (f'-{days_old} days',))

            deleted_count = cursor.rowcount
            if deleted_count > 0:
                logger.info(f"Удалено {deleted_count} старых сканирований")
            return deleted_count

    def get_vulnerability_stats(self):
        """Подробная статистика по уязвимостям"""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute('''
            SELECT 
                vuln_type,
                severity,
                COUNT(*) as count,
                AVG(risk_score) as avg_risk
            FROM vulnerabilities
            GROUP BY vuln_type, severity
            ORDER BY severity DESC, count DESC
            ''')

            return [dict(row) for row in cursor.fetchall()]

    def get_recent_vulnerabilities(self, limit=10):
        """Получение последних уязвимостей"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT v.*, s.url, s.timestamp 
                FROM vulnerabilities v
                JOIN scans s ON v.scan_id = s.scan_id
                ORDER BY s.timestamp DESC
                LIMIT ?
            ''', (limit,))

            vulnerabilities = []
            for row in cursor.fetchall():
                vuln = dict(row)
                evidence_str = vuln.get('evidence', '[]')
                try:
                    vuln['evidence'] = json.loads(evidence_str)
                except (json.JSONDecodeError, TypeError):
                    vuln['evidence'] = []
                vulnerabilities.append(vuln)

            return vulnerabilities