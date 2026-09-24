from flask import Flask, request, Response, render_template_string

app = Flask(__name__)

INDEX_TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>Test Site</title></head>
<body>
    <h1>Welcome to the Test Site</h1>
    <a href="/page1">Internal Link 1</a>
    <a href="/nested/page2">Nested Internal Link</a>
    <a href="https://example.com">External Link</a>
    
    <form action="/submit" method="POST">
        <input type="text" name="username">
        <input type="password" name="password">
        <input type="submit" value="Login">
    </form>
    
    <a href="/resource.txt">Non-HTML Resource</a>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(INDEX_TEMPLATE)

@app.route('/page1')
def page1():
    param = request.args.get('param', 'default')
    return f"<html><body><h1>Page 1</h1><p>Param: {param}</p><a href='/'>Home</a></body></html>"

@app.route('/nested/page2')
def nested_page2():
    return "<html><body><h1>Nested Page 2</h1><a href='/page1?param=test'>Link with Param</a></body></html>"

@app.route('/submit', methods=['POST'])
def submit():
    return "<html><body><h1>Submitted</h1><a href='/'>Home</a></body></html>"

@app.route('/resource.txt')
def resource():
    return Response("This is a plain text file.", mimetype="text/plain")

def run_server(port=5000):
    app.run(host='127.0.0.1', port=port, debug=False)

if __name__ == '__main__':
    run_server()
