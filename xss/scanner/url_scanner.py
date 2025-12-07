import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import logging
from .xss_detector import XSSDetector
import time

logger = logging.getLogger(__name__)


class URLScanner:
    """Сканер URL на наличие XSS уязвимостей"""

    def __init__(self):
        self.xss_detector = XSSDetector()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

    def scan_url(self, url, scan_type='fast'):

        try:

            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url

            parsed_url = urlparse(url)
            if not parsed_url.netloc:
                return {'error': 'Неверный URL'}

            results = {
                'url': url,
                'scan_type': scan_type,
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'vulnerabilities': [],
                'scan_summary': {}
            }

            # Быстрое сканирование
            if scan_type == 'fast':
                self._fast_scan(url, results)
            # Глубокое сканирование
            else:
                self._deep_scan(url, results)


            self._generate_summary(results)

            return results

        except Exception as e:
            logger.error(f"Ошибка при сканировании {url}: {str(e)}")
            return {'error': f'Ошибка сканирования: {str(e)}'}

    def _fast_scan(self, url, results):

        try:
            response = self.session.get(url, timeout=10)
            response.raise_for_status()


            html_scan = self.xss_detector.check(response.text)
            if html_scan['is_threat']:
                results['vulnerabilities'].append({
                    'type': 'reflected_xss',
                    'severity': html_scan['threat_level'],
                    'description': 'Обнаружены потенциальные XSS паттерны в HTML',
                    'evidence': html_scan['threats_found'][:3],
                    'risk_score': self._calculate_risk_score(html_scan['threat_level'])
                })

            # Проверяем параметры URL
            parsed_url = urlparse(url)
            query_params = self._parse_query_params(parsed_url.query)

            for param, value in query_params.items():
                param_scan = self.xss_detector.scan_input(value)
                if param_scan['is_threat']:
                    results['vulnerabilities'].append({
                        'type': 'reflected_xss',
                        'severity': param_scan['threat_level'],
                        'description': f'XSS в параметре URL: {param}',
                        'location': f'URL параметр: {param}',
                        'evidence': param_scan['threats_found'][:3],
                        'risk_score': self._calculate_risk_score(param_scan['threat_level'])
                    })

        except requests.RequestException as e:
            results['error'] = f'Ошибка подключения: {str(e)}'

    def _deep_scan(self, url, results):
        """Глубокое сканирование URL"""
        try:
            response = self.session.get(url, timeout=15)
            response.raise_for_status()

            soup = BeautifulSoup(response.text, 'html.parser')


            forms = soup.find_all('form')
            for i, form in enumerate(forms):
                form_scan = self._scan_form(form, url)
                if form_scan:
                    results['vulnerabilities'].extend(form_scan)

            # Проверяем ссылки
            links = soup.find_all('a', href=True)
            for link in links[:50]:
                href = link['href']
                link_scan = self.xss_detector.scan_input(href)
                if link_scan['is_threat']:
                    results['vulnerabilities'].append({
                        'type': 'stored_xss',
                        'severity': link_scan['threat_level'],
                        'description': 'Потенциальная XSS в ссылках',
                        'location': f'Ссылка: {href[:100]}...',
                        'evidence': link_scan['threats_found'][:3],
                        'risk_score': self._calculate_risk_score(link_scan['threat_level'])
                    })

            # Проверяем скрипты
            scripts = soup.find_all('script')
            for script in scripts:
                if script.string:
                    script_scan = self.xss_detector.check(script.string)
                    if script_scan['is_threat']:
                        results['vulnerabilities'].append({
                            'type': 'dom_xss',
                            'severity': script_scan['threat_level'],
                            'description': 'Потенциальная DOM-based XSS',
                            'evidence': script_scan['threats_found'][:3],
                            'risk_score': self._calculate_risk_score(script_scan['threat_level'])
                        })

        except requests.RequestException as e:
            results['error'] = f'Ошибка подключения: {str(e)}'

    def _scan_form(self, form, base_url):
        """Сканирует форму на уязвимости"""
        vulnerabilities = []

        try:
            action = form.get('action', '')
            method = form.get('method', 'get').lower()
            form_url = urljoin(base_url, action)


            inputs = form.find_all('input')
            for input_field in inputs:
                input_name = input_field.get('name', '')
                input_value = input_field.get('value', '')

                if input_name:
                    value_scan = self.xss_detector.scan_input(input_value)
                    if value_scan['is_threat']:
                        vulnerabilities.append({
                            'type': 'stored_xss',
                            'severity': value_scan['threat_level'],
                            'description': f'XSS в значении поля формы: {input_name}',
                            'location': f'Форма: {form_url}, поле: {input_name}',
                            'evidence': value_scan['threats_found'][:3],
                            'risk_score': self._calculate_risk_score(value_scan['threat_level'])
                        })

        except Exception as e:
            logger.error(f"Ошибка при сканировании формы: {str(e)}")

        return vulnerabilities

    def _parse_query_params(self, query_string):
        """Парсит параметры URL"""
        from urllib.parse import parse_qs
        params = {}
        try:
            parsed = parse_qs(query_string)
            for key, values in parsed.items():
                if values:
                    params[key] = values[0]
        except:
            pass
        return params

    def _calculate_risk_score(self, threat_level):
        """Рассчитывает оценку риска"""
        scores = {'high': 3, 'medium': 2, 'low': 1}
        return scores.get(threat_level, 0)

    def _generate_summary(self, results):
        """Генерирует сводку сканирования"""
        vulnerabilities = results.get('vulnerabilities', [])

        summary = {
            'total_vulnerabilities': len(vulnerabilities),
            'high_risk': len([v for v in vulnerabilities if v.get('severity') == 'high']),
            'medium_risk': len([v for v in vulnerabilities if v.get('severity') == 'medium']),
            'low_risk': len([v for v in vulnerabilities if v.get('severity') == 'low']),
            'total_risk_score': sum(v.get('risk_score', 0) for v in vulnerabilities)
        }


        if summary['high_risk'] > 0:
            summary['security_level'] = 'Высокий риск'
        elif summary['medium_risk'] > 0:
            summary['security_level'] = 'Средний риск'
        elif summary['low_risk'] > 0:
            summary['security_level'] = 'Низкий риск'
        else:
            summary['security_level'] = 'Безопасно'

        results['scan_summary'] = summary