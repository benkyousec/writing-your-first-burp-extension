from flask import Flask, request
from hashlib import sha256

app = Flask(__name__)

@app.route('/ping')
def ping():
    return '<h1>Pong</h1>'

@app.route('/test', methods=['POST'])
def test():
    sig = request.headers.get('Signature')
    body = request.get_data()
    computedHmac = sha256(body).hexdigest()
    if (sig.strip() == computedHmac):
        data = request.form.get('data')
        return data
    else:
        return 'Invalid signature'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)