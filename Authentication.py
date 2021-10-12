from flask import Flask, request, jsonify, make_response
import jwt
import datetime
from functools import wraps

app =Flask(__name__)
app.config['SECRET_KEY'] = 'thisisthesecretkey'

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.args.get('token')

        if not token:
            return jsonify({'message' : 'Your token is Missing'}),403

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
        except:
            return jsonify({'message' : 'Your token is invalid or Expired'}),403

        return f(*args, **kwargs)

    return decorated

@app.route('/unprotected')
def unprotected():
    return jsonify({'message' : 'This is Unprotected anyone can visit here.'})

@app.route('/protected')
@token_required
def protected():
    return jsonify({'message' : 'Person only with Valid Token can visit here.'})

@app.route('/login')
def login():
    auth = request.authorization

    if auth and auth.password == 'password':
        token = jwt.encode({'user': auth.username, 'exp' :datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])

        return jsonify({'Token': token.decode('UTF-8')})

    return make_response('Could not verify!', 401, {'WWW-Authenticate':'basic realm="Login Required"'})


if __name__== '__main__':
    app.run(debug=True)