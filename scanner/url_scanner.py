import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
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

            # Общие проверки для всех типов сканирования
            self._check_url_itself(url, results)

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

    def _check_url_itself(self, url, results):
        """Проверяет сам URL на XSS (общая проверка для всех типов сканирования)"""
        try:
            parsed_url = urlparse(url)

            # Проверяем параметры запроса
            query_params = self._parse_query_params(parsed_url.query)
            for param, value in query_params.items():
                param_scan = self.xss_detector.check(value)
                if param_scan['is_threat']:
                    results['vulnerabilities'].append({
                        'type': 'reflected_xss',
                        'severity': param_scan['threat_level'],
                        'description': f'XSS в параметре URL: {param}',
                        'location': f'Параметр: {param}',
                        'evidence': param_scan['threats_found'][:3],
                        'risk_score': self._calculate_risk_score(param_scan['threat_level'])
                    })

        except Exception as e:
            logger.error(f"Ошибка при проверке URL: {str(e)}")

    def _fast_scan(self, url, results):
        """Быстрое сканирование - только проверка ответа сервера на отраженные параметры"""
        try:
            # Делаем запрос и проверяем ответ
            response = self.session.get(url, timeout=10, allow_redirects=True)
            response.raise_for_status()

            # Проверяем HTML ответ на наличие отраженных параметров
            parsed_url = urlparse(url)
            query_params = self._parse_query_params(parsed_url.query)

            if query_params:
                response_text = response.text.lower()
                for param, value in query_params.items():
                    if value and value.lower() in response_text:
                        # Проверяем значение параметра на XSS
                        param_scan = self.xss_detector.check(value)
                        if param_scan['is_threat']:
                            results['vulnerabilities'].append({
                                'type': 'reflected_xss',
                                'severity': param_scan['threat_level'],
                                'description': f'Параметр "{param}" отражается в ответе сервера',
                                'location': f'Параметр: {param}',
                                'evidence': param_scan['threats_found'][:3],
                                'risk_score': self._calculate_risk_score(param_scan['threat_level'])
                            })

        except requests.RequestException as e:
            results['error'] = f'Ошибка подключения: {str(e)}'
        except Exception as e:
            logger.error(f"Ошибка в быстром сканировании: {str(e)}")

    def _deep_scan(self, url, results):
        """Глубокое сканирование - полный анализ страницы на потенциальные уязвимости"""
        try:
            # Сначала делаем то же, что и быстрое сканирование
            self._fast_scan(url, results)

            # Дополнительные глубокие проверки
            response = self.session.get(url, timeout=15)
            response.raise_for_status()

            soup = BeautifulSoup(response.text, 'html.parser')

            # 1. Проверяем формы на потенциальные уязвимости
            forms_found = soup.find_all('form')
            if forms_found:
                # Найдены формы - потенциальная уязвимость
                results['vulnerabilities'].append({
                    'type': 'potential_xss',
                    'severity': 'low',
                    'description': f'На странице найдены формы ({len(forms_found)} шт.)',
                    'location': 'Формы на странице',
                    'evidence': [f'Найдено {len(forms_found)} форм, которые могут быть уязвимы'],
                    'risk_score': self._calculate_risk_score('low')
                })

                # Детальная проверка каждой формы
                for i, form in enumerate(forms_found[:3]):  # Проверяем первые 3 формы
                    form_details = self._analyze_form(form, url)
                    if form_details:
                        results['vulnerabilities'].extend(form_details)

            # 2. Проверяем input поля без валидации
            inputs = soup.find_all('input')
            text_inputs = [inp for inp in inputs if inp.get('type', 'text') in ['text', 'search', 'email', 'password']]

            if text_inputs:
                unvalidated_inputs = []
                for inp in text_inputs[:5]:  # Проверяем первые 5 полей
                    if not inp.get('pattern') and not inp.get('maxlength'):
                        input_name = inp.get('name', 'без имени')
                        unvalidated_inputs.append(input_name)

                if unvalidated_inputs:
                    results['vulnerabilities'].append({
                        'type': 'potential_xss',
                        'severity': 'medium',
                        'description': f'Найдены поля ввода без валидации: {", ".join(unvalidated_inputs[:3])}',
                        'location': 'Поля ввода на странице',
                        'evidence': ['Отсутствует валидация ввода (pattern, maxlength)'],
                        'risk_score': self._calculate_risk_score('medium')
                    })

            # 3. Проверяем скрипты на использование опасных функций
            scripts = soup.find_all('script')
            dangerous_scripts = []

            for script in scripts:
                if script.string:
                    script_text = script.string.lower()
                    dangerous_patterns = [
                        'innerhtml', 'outerhtml', 'document.write',
                        'eval(', 'settimeout(', 'setinterval('
                    ]

                    for pattern in dangerous_patterns:
                        if pattern in script_text:
                            dangerous_scripts.append(pattern)
                            break

            if dangerous_scripts:
                results['vulnerabilities'].append({
                    'type': 'dom_xss',
                    'severity': 'high',
                    'description': f'В скриптах найдены опасные функции: {", ".join(set(dangerous_scripts))}',
                    'location': 'JavaScript на странице',
                    'evidence': ['Использование опасных DOM-функций'],
                    'risk_score': self._calculate_risk_score('high')
                })

            # 4. Проверяем ссылки с параметрами
            links = soup.find_all('a', href=True)
            links_with_params = []

            for link in links[:20]:  # Проверяем первые 20 ссылок
                href = link['href']
                if '?' in href and '=' in href:
                    links_with_params.append(href[:50] + '...' if len(href) > 50 else href)

            if links_with_params:
                results['vulnerabilities'].append({
                    'type': 'potential_xss',
                    'severity': 'low',
                    'description': f'Найдены ссылки с параметрами ({len(links_with_params)} шт.)',
                    'location': 'Ссылки на странице',
                    'evidence': links_with_params[:3],
                    'risk_score': self._calculate_risk_score('low')
                })

            # 5. Проверяем атрибуты событий
            event_attributes = ['onerror', 'onclick', 'onload', 'onmouseover',
                                'onsubmit', 'onchange', 'onfocus', 'onblur']
            elements_with_events = []

            for event in event_attributes:
                elements = soup.find_all(attrs={event: True})
                if elements:
                    elements_with_events.append(f'{event}: {len(elements)}')

            if elements_with_events:
                results['vulnerabilities'].append({
                    'type': 'potential_xss',
                    'severity': 'medium',
                    'description': f'Найдены элементы с обработчиками событий',
                    'location': 'Элементы с атрибутами событий',
                    'evidence': elements_with_events[:3],
                    'risk_score': self._calculate_risk_score('medium')
                })

            # 6. Проверяем Content Security Policy
            if 'content-security-policy' not in response.headers:
                results['vulnerabilities'].append({
                    'type': 'security_header',
                    'severity': 'medium',
                    'description': 'Отсутствует заголовок Content-Security-Policy',
                    'location': 'HTTP заголовки',
                    'evidence': ['CSP не настроен'],
                    'risk_score': self._calculate_risk_score('medium')
                })

        except requests.RequestException as e:
            results['error'] = f'Ошибка подключения: {str(e)}'
        except Exception as e:
            logger.error(f"Ошибка в глубоком сканировании: {str(e)}")

    def _analyze_form(self, form, base_url):
        """Анализирует форму на потенциальные уязвимости"""
        vulnerabilities = []
        try:
            action = form.get('action', '')
            method = form.get('method', 'get').lower()
            form_url = urljoin(base_url, action)

            inputs = form.find_all('input')
            text_inputs = []

            for inp in inputs:
                input_type = inp.get('type', 'text')
                input_name = inp.get('name', '')

                if input_type in ['text', 'search', 'email', 'textarea', '']:
                    text_inputs.append({
                        'name': input_name,
                        'type': input_type,
                        'has_pattern': bool(inp.get('pattern')),
                        'has_maxlength': bool(inp.get('maxlength')),
                        'has_required': bool(inp.get('required'))
                    })

            if text_inputs:
                # Форма имеет текстовые поля - потенциальная уязвимость
                vuln_description = f'Форма с методом {method.upper()} содержит поля ввода'

                vulnerabilities.append({
                    'type': 'potential_xss',
                    'severity': 'low',
                    'description': vuln_description,
                    'location': f'Форма: {form_url}',
                    'evidence': [f'Найдено {len(text_inputs)} текстовых полей'],
                    'risk_score': self._calculate_risk_score('low')
                })

                # Проверяем конкретные поля
                for inp_info in text_inputs[:3]:
                    if not inp_info['has_pattern'] and not inp_info['has_maxlength']:
                        vulnerabilities.append({
                            'type': 'potential_xss',
                            'severity': 'medium',
                            'description': f'Поле "{inp_info["name"]}" без валидации',
                            'location': f'Форма: {form_url}, поле: {inp_info["name"]}',
                            'evidence': ['Отсутствует pattern и maxlength атрибуты'],
                            'risk_score': self._calculate_risk_score('medium')
                        })

        except Exception as e:
            logger.error(f"Ошибка при анализе формы: {str(e)}")

        return vulnerabilities

    def _parse_query_params(self, query_string):
        """Парсит параметры URL"""
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

        # Определяем уровень безопасности
        if summary['high_risk'] > 0:
            summary['security_level'] = 'Высокий риск'
        elif summary['medium_risk'] > 0:
            summary['security_level'] = 'Средний риск'
        elif summary['low_risk'] > 0:
            summary['security_level'] = 'Низкий риск'
        else:
            summary['security_level'] = 'Безопасно'

        results['scan_summary'] = summary