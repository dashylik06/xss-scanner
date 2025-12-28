import re
import logging
from urllib.parse import unquote
import html

logger = logging.getLogger(__name__)


class XSSDetector:
    """Класс для обнаружения XSS-атак"""

    def __init__(self):
        # Паттерны для обнаружения XSS
        self.patterns = [
            # Базовые теги скриптов
            r'<script.*?>.*?</script>',
            r'<script.*?>',

            # События JavaScript (ВСЕ события начинающиеся с on)
            r'on\w+\s*=',
            r'onload\s*=',
            r'onerror\s*=',
            r'onclick\s*=',
            r'onmouseover\s*=',
            r'onsubmit\s*=',
            r'onchange\s*=',
            r'onfocus\s*=',
            r'onblur\s*=',

            # Протоколы выполнения
            r'javascript:',
            r'vbscript:',
            r'data:\s*text/html',

            # Опасные HTML-теги
            r'<\s*iframe',
            r'<\s*embed',
            r'<\s*object',
            r'<\s*form',
            r'<\s*meta',

            # SVG и MathML инъекции
            r'<svg.*?>',
            r'<math.*?>',
            r'<image.*?>',

            # Функции JavaScript
            r'eval\s*\(',
            r'alert\s*\(',
            r'prompt\s*\(',
            r'confirm\s*\(',
            r'console\.log\s*\(',
            r'document\.write\s*\(',
            r'innerHTML\s*=',
            r'outerHTML\s*=',

            # Работа с DOM и cookies
            r'document\.cookie',
            r'window\.location',
            r'window\.open',
            r'location\.href',
            r'location\.replace',

            # Кодированные атаки
            r'&#x?\d+;?',
            r'%3Cscript',
            r'%3C/script',

            # CSS выражения
            r'expression\s*\(',
            r'url\s*\(.*javascript:',

            # Атрибуты стиля
            r'style\s*=.*expression',
            r'style\s*=.*javascript:',
        ]

        self.compiled_patterns = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in self.patterns]

        # Паттерны высокого риска
        self.high_risk_patterns = [
            r'<script.*?>',
            r'javascript:',
            r'eval\s*\(',
            r'document\.cookie',
            r'document\.write',
            r'innerHTML\s*=',
            r'data:\s*text/html',
        ]

        # Паттерны среднего риска
        self.medium_risk_patterns = [
            r'on\w+\s*=',
            r'<iframe',
            r'<embed',
            r'<object',
            r'alert\s*\(',
            r'prompt\s*\(',
            r'confirm\s*\(',
        ]

        self.high_risk_compiled = [re.compile(p, re.IGNORECASE) for p in self.high_risk_patterns]
        self.medium_risk_compiled = [re.compile(p, re.IGNORECASE) for p in self.medium_risk_patterns]

        logger.info("XSS Detector initialized with %d patterns", len(self.patterns))

    def check(self, text):
        """
        Проверяет текст на наличие XSS-угроз

        Args:
            text (str): Входной текст для проверки

        Returns:
            dict: Результаты проверки
        """
        if not isinstance(text, str):
            text = str(text)

        threats_found = []
        threat_level = "low"

        # Декодируем URL-кодирование
        decoded_text = unquote(text)

        # Также проверяем HTML-сущности
        html_decoded = html.unescape(decoded_text)

        # Проверяем все тексты
        texts_to_check = [text, decoded_text, html_decoded]

        for check_text in texts_to_check:
            for pattern in self.compiled_patterns:
                matches = pattern.findall(check_text)
                if matches:
                    threats_found.extend(matches)

        # Удаляем дубликаты
        threats_found = list(set(threats_found))

        if threats_found:
            # Определяем уровень угрозы
            text_for_check = html_decoded.lower()

            # Проверяем высокий риск
            high_risk_found = False
            for pattern in self.high_risk_compiled:
                if pattern.search(text_for_check):
                    high_risk_found = True
                    break

            if high_risk_found:
                threat_level = "high"
            else:
                # Проверяем средний риск
                medium_risk_found = False
                for pattern in self.medium_risk_compiled:
                    if pattern.search(text_for_check):
                        medium_risk_found = True
                        break

                if medium_risk_found:
                    threat_level = "medium"
                else:
                    threat_level = "low"

        return {
            'is_threat': len(threats_found) > 0,
            'threat_level': threat_level,
            'threats_found': threats_found[:10],  # Ограничиваем количество для отчета
            'threat_count': len(threats_found)
        }

    def scan_input(self, input_text):
        """
        Сканирует пользовательский ввод на XSS

        Args:
            input_text (str): Входной текст

        Returns:
            dict: Результаты сканирования
        """
        result = self.check(input_text)

        # Дополнительная проверка для разных типов инъекций
        checks = {
            'script_tags': bool(re.search(r'<script.*?>', input_text, re.IGNORECASE)),
            'event_handlers': bool(re.search(r'on\w+\s*=', input_text, re.IGNORECASE)),
            'javascript_protocol': bool(re.search(r'javascript:', input_text, re.IGNORECASE)),
            'dangerous_tags': bool(re.search(r'<(iframe|embed|object|form|svg|math)', input_text, re.IGNORECASE)),
            'js_functions': bool(
                re.search(r'(eval|alert|prompt|confirm|document\.write)\s*\(', input_text, re.IGNORECASE)),
            'dom_manipulation': bool(re.search(r'(innerHTML|outerHTML)\s*=', input_text, re.IGNORECASE)),
            'url_encoded': bool(re.search(r'%3C|%3E|%22|%27|%28|%29', input_text)),
        }

        result['detailed_checks'] = checks

        return result