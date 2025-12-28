from flask import Flask, request

app = Flask(__name__)

@app.route('/')
def index():
    q = request.args.get('q', '')
    # УЯЗВИМЫЙ КОД - отражаем без экранирования
    return f'<html><body><h1>Search results for: {q}</h1></body></html>'

@app.route('/safe')
def safe():
    q = request.args.get('q', '')
    # БЕЗОПАСНЫЙ КОД - экранируем
    from html import escape
    return f'<html><body><h1>Search results for: {escape(q)}</h1></body></html>'

if __name__ == '__main__':
    app.run(port=8080)