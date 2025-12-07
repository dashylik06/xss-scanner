import re
import logging
from urllib.parse import unquote, urlparse
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

            # События JavaScript
            r'on\w+\s*=',
            r'onload\s*=',
            r'onerror\s*=',
            r'onclick\s*=',
            r'onmouseover\s*=',

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

            # Функции JavaScript
            r'eval\s*\(',
            r'alert\s*\(',
            r'prompt\s*\(',
            r'confirm\s*\(',
            r'console\.log\s*\(',

            # Работа с DOM и cookies
            r'document\.cookie',
            r'document\.write',
            r'window\.location',
            r'window\.open',
            r'location\.href',

            # SVG-инъекции
            r'<svg.*?>',
            r'<math.*?>',
        ]

        self.compiled_patterns = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in self.patterns]
        logger.info("XSS Detector initialized with %d patterns", len(self.patterns))

    def check(self, text):
        """
        Проверяет текст на наличие XSS-угроз


        """
        if not isinstance(text, str):
            text = str(text)

        threats_found = []
        threat_level = "low"


        decoded_text = unquote(text)


        for pattern in self.compiled_patterns:
            matches = pattern.findall(decoded_text)
            if matches:
                threats_found.extend(matches)


        if any(tag in decoded_text.lower() for tag in ['<script', 'javascript:', 'onload=']):
            threat_level = "high"
        elif threats_found:
            threat_level = "medium"

        return {
            'is_threat': len(threats_found) > 0,
            'threat_level': threat_level,
            'threats_found': threats_found[:10],  # Ограничиваем количество для отчета
            'threat_count': len(threats_found)
        }

    def scan_input(self, input_text):
        """
        Сканирует пользовательский ввод на XSS


        """
        result = self.check(input_text)

        # Дополнительная проверка
        checks = {
            'script_tags': bool(re.search(r'<script.*?>', input_text, re.IGNORECASE)),
            'event_handlers': bool(re.search(r'on\w+\s*=', input_text, re.IGNORECASE)),
            'javascript_protocol': bool(re.search(r'javascript:', input_text, re.IGNORECASE)),
            'dangerous_tags': bool(re.search(r'<(iframe|embed|object|form)', input_text, re.IGNORECASE))
        }

        result['detailed_checks'] = checks
        return result