from sqlalchemy import create_engine
import os, sqlalchemy
import pymysql

pymysql.install_as_MySQLdb()

class ReplDBSQL(object):
    def __init__(self, db_uri: str):
        self.db_uri = db_uri
        self.engine = create_engine(db_uri, pool_size=5, pool_recycle=3600)

    def run(self, query: str, vals: dict={}):
        conn = self.engine.connect()
        query = conn.execute(sqlalchemy.text(query), vals)
        try:
            res = query.fetchall()
        except:
            res = None
        conn.commit()
        conn.close()
        if res:
            return [dict(row._mapping) for row in res]
        return []

# main.py
#from gevent import monkey
#monkey.patch_all()
#from dotenv import load_dotenv; load_dotenv() #DEV
from flask import Flask, jsonify, request, render_template, session, redirect, send_file
#from flask_socketio import SocketIO
#from replemail import ReplEmail
from mjms import MJMS
from datetime import datetime
#from db import ReplDBSQL
from uuid import uuid4
#from replit import db as repldb
import requests
import hashlib
import string
import qrcode
import pyotp
import time
import imj
import io

# flask setup
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
#socketio = SocketIO(app)
#socketio.init_app(app, cors_allowed_origins='*')

repldb = {}

# db setup
db = ReplDBSQL(os.getenv('DB_URI'))
db.run('''
CREATE TABLE IF NOT EXISTS users (
    ID INTEGER PRIMARY KEY AUTO_INCREMENT,
    USERNAME TEXT NOT NULL,
    PASSHASH TEXT NOT NULL,
    EMAIL TEXT,
    EMAIL_VERIFIED BOOL,
    EMAIL_TOKEN TEXT,
    FULLNAME TEXT,
    CREATED INTEGER NOT NULL
)
''')
db.run('''
CREATE TABLE IF NOT EXISTS tokens (
    TOKEN VARCHAR(36) PRIMARY KEY NOT NULL,
    USERID INTEGER NOT NULL,
    CREATED INTEGER NOT NULL,
    NAME TEXT
)
''')
db.run('''
CREATE TABLE IF NOT EXISTS avatars (
    ID INTEGER PRIMARY KEY AUTO_INCREMENT,
    USERNAME TEXT NOT NULL,
    URL TEXT NOT NULL
)
''')
db.run('''
CREATE TABLE IF NOT EXISTS mfa (
    ID INTEGER PRIMARY KEY AUTO_INCREMENT,
    USERID INTEGER NOT NULL,
    SECRET TEXT NOT NULL,
    VERIFIED BOOL NOT NULL
)
''')

# replemail
#replemail = ReplEmail('MarcusWeinberger', os.getenv('REPLEMAIL'))
mjms = MJMS(os.getenv('MJMS'))
mjms.base = 'https://mailsrv.marcusj.org/api' # shouldn't be needed but to ensure

# general stuff
sha256 = lambda s: hashlib.sha256(s.encode()).hexdigest()
uuid = lambda: str(uuid4())
user_chars = list(string.ascii_letters + string.digits + '-_.')
valid_user = lambda u: all([c in user_chars for c in u])
timestamp = lambda: datetime.utcnow().timestamp()
to_date = lambda ts: datetime.utcfromtimestamp(ts)

flask_funcs = {
    'sha256': sha256,
    'valid_user': valid_user,
    'to_date': to_date,
}

# db functions
class get_user:
    def by_user(username):
        res = db.run('SELECT * FROM users WHERE USERNAME = :u', {'u': username})
        return res[0] if not res == [] else False
    def by_login(username, password):
        res = db.run('SELECT * FROM users WHERE USERNAME = :u AND PASSHASH = :p', {
            'u': username,
            'p': sha256(password),
        })
        return res[0] if not res == [] else False
    def by_id(id):
        res = db.run('SELECT * FROM users WHERE ID = :i', {'i': id})
        return res[0] if not res == [] else False
    def by_token(master):
        if (tkns := tokens.by_token(master)):
            userid = tkns['USERID']
            return get_user.by_id(userid)
        return False

class tokens:
    def by_userid(uid):
        return db.run('SELECT * FROM tokens WHERE USERID = :u', {'u': uid})
    def by_user(username):
        uid = get_user.by_user(username)['ID']
        return tokens.by_userid(uid)
    def by_token(token):
        res = db.run('SELECT * FROM tokens WHERE TOKEN = :t', {'t': token})
        return res[0] if not res == [] else False
    def get_master_token(userid):
        return db.run('SELECT TOKEN FROM tokens WHERE USERID = :u AND NAME = :n', {'u': userid, 'n': 'master'})[0]['TOKEN']

def user_login(username, password):
    user = get_user.by_login(username, password)
    if user:
        user['TOKEN'] = tokens.get_master_token(user['ID'])
    return user

def check_username(username):
    """Returns False if username is invalid or taken."""
    if valid_user(username):
        return not get_user.by_user(username) # get_user.by_username returns False if user not found
    return False

def register_user(username, password, email=None, fullname=None):
    if not check_username(username):
        return False
    db.run('INSERT INTO users (USERNAME, PASSHASH, EMAIL, FULLNAME, CREATED) VALUES (:u, :p, :e, :f, :c)', {
        'u': username,
        'p': sha256(password),
        'e': email,
        'f': fullname,
        'c': timestamp()
    })
    user = get_user.by_user(username)
    if user['EMAIL']:
        r = mjms.verify_email(user['EMAIL'])
        tkn = r['token']
        db.run('UPDATE users SET EMAIL_TOKEN = :e WHERE ID = :i', {'e': tkn, 'i': user['ID']})
    token = register_token(user['ID'], name='master')
    user['TOKEN'] = token['TOKEN']
    return user

def get_avatar(user):
    if (res := db.run('SELECT URL FROM avatars WHERE USERNAME = :u', {'u': user})) == []:
        return None
    return res[0]

def set_avatar(user, image_url):
    if get_avatar(user):
        db.run('UPDATE avatars SET URL = :url WHERE USERNAME = :user', {'url': image_url, 'user': user})
    else:
        db.run('INSERT INTO avatars (USERNAME, URL) VALUES (:user, :url)', {'user': user, 'url': image_url})
    return True

def delete_user(userid):
    db.run('DELETE FROM users WHERE ID = :i', {'i': userid})
    db.run('DELETE FROM tokens WHERE USERID = :u', {'u': userid})

def register_token(userid, name=None):
    if not (tkn := db.run('SELECT TOKEN FROM tokens WHERE USERID = :u AND NAME = :n', {'u': userid, 'n': name})) == []:
        return tokens.by_token(tkn[0]['TOKEN']) 
    tkn = uuid()
    db.run('INSERT INTO tokens (TOKEN, USERID, CREATED, NAME) VALUES (:t, :u, :c, :n)', {
        't': tkn,
        'u': userid,
        'c': timestamp(),
        'n': name
    })
    return tokens.by_token(tkn)

def get_mfa(user):
    res = db.run('SELECT * FROM mfa WHERE USERID = :u', {'u': user['ID']})
    return res[0] if not res == [] else False

# api auth functions

def api_auth():
    if (tkn := request.form.get('token')):
        user = get_user.by_token(tkn)
    elif (tkn := session.get('token')):
        user = get_user.by_token(tkn)
    else:
        user = session.get('user')
    if user and not 'TOKEN' in user:
        user['TOKEN'] = tokens.get_master_token(user['ID'])
    if user and 'ID' in user:
        user['HAS_MFA'] = (get_mfa(user) or {}).get('VERIFIED', False)
    return user

# app
@app.route('/')
def app_index():
    return render_template('index.html', user=api_auth(), redir=request.args.get('redir', ''), msg=request.args.get('msg', ''), logout=request.args.get('logout', 'false'), **flask_funcs)

@app.route('/demo')
def app_demo():
    return render_template('demo.html')

@app.route('/avatar/<username>')
def app_avatar(username):
    if (url := get_avatar(username)):
        return redirect(url)
    return '', 404

@app.route('/auth/<domain>')
@app.route('/auth/')
def app_auth(domain='this site'):
    return render_template('authpage.html', domain=domain, user=api_auth(), **flask_funcs)

@app.route('/callback/verify/<token>')
def callback_verify(token):
    try:
        db.run('UPDATE users SET EMAIL_VERIFIED = :e WHERE TOKEN = :t', {'e': True, 't': token})
        return redirect('https://auth.marcusj.org/?msg=email_verified')
    except:
        return redirect('https://auth.marcusj.org/')

@app.route('/forgotpass/<token>')
def app_forgotpass(token):
    valid = repldb.get(token)
    if not valid:
        return redirect('https://auth.marcusj.org')
    if not time.time() - valid['time'] < (60 * 60 * 2):
        return redirect('https://auth.marcusj.org')
    return render_template('forgotpass.html', token=token)

@app.route('/logout')
def app_logout():
    session.clear()
    return redirect('https://auth.marcusj.org/?logout=true')

@app.route('/static/auth.js')
@app.route('/auth.js')
def app_auth_js():
    return render_template('auth.js')

@app.route('/mfa/qr')
def app_qr():
    if (user := api_auth()):
        if (mfa := get_mfa(user)):
            if not mfa['VERIFIED']:
                text = pyotp.totp.TOTP(mfa['SECRET']).provisioning_uri(user['USERNAME'], issuer_name='auth.marcusj.org')
                img = qrcode.make(text)
                img_io = io.BytesIO()
                img.save(img_io, 'JPEG')
                img_io.seek(0)

                return send_file(img_io, mimetype='image/jpeg')
            else:
                return 'err: mfa already verified. please contact marcus@marcusj.org if you need to reset your mfa'
        else:
            return 'err: no mfa for user'
    return 'err: not authenticated'

# api
@app.route('/api/login', methods=['POST'])
def api_login():
    user = user_login(request.form['username'], request.form['password'])
    if user:
        mfa = get_mfa(user)
        if not mfa['VERIFIED']:
            session['user'] = user
            return jsonify({'success': True, 'user': user})
        # do mfa flow
        if (code := request.form.get('mfa')):
            totp = pyotp.TOTP(mfa['SECRET'])
            if totp.verify(code):
                session['user'] = user
                return jsonify({'success': True, 'user': user})
            return jsonify({'success': False, 'error': 'invalid code'})
        return jsonify({'success': False, 'mfa': True})
    else:
        return jsonify({'success': False, 'error': 'invalid login'})

@app.route('/api/signup', methods=['POST'])
def api_signup():
    username = request.form['username']
    if not check_username(username):
        return jsonify({'success': False, 'error': 'username taken'})
    password = request.form['password']
    email = request.form.get('email')
    fullname = request.form.get('fullname')
    user = register_user(username, password, email=email, fullname=fullname)
    session['user'] = user
    return jsonify({'success': bool(user), 'user': user})

@app.route('/api/changepass', methods=['POST'])
def api_change_pass():
    user = api_auth()
    if user:
        newpass = sha256(request.form['password'])
        db.run('UPDATE users SET PASSHASH = :p WHERE ID = :i', {
            'p': newpass,
            'i': user['ID']
        })
        return jsonify({'changed': True})
    return jsonify({'changed': False})

@app.route('/api/mfa/enable', methods=['POST'])
def api_mfa_enable():
    if (user := api_auth()):
        if (mfa := get_mfa(user)):
            if mfa['VERIFIED']:
                return jsonify({'ok': False, 'error': 'mfa has already been added for this account'})
            # else, delete old mfa
            db.run('DELETE FROM mfa WHERE USERID = :u AND SECRET = :s', {
                'u': user['ID'],
                's': mfa['SECRET']
            })
        # create new mfa
        secret = pyotp.random_base32()
        db.run('INSERT INTO mfa (USERID, SECRET, VERIFIED) VALUES (:u, :s, :v)', {
            'u': user['ID'],
            's': secret,
            'v': False
        })
        return jsonify({'ok': True}) # next step is to verify
    else:
        return jsonify({'ok': False, 'error': 'bad/no authentication'})

@app.route('/api/mfa/verify', methods=['POST'])
def api_mfa_verify():
    if (user := api_auth()):
        if (mfa := get_mfa(user)):
            totp = pyotp.TOTP(mfa['SECRET'])
            if totp.verify(request.form['code']):
                db.run('UPDATE mfa SET VERIFIED = :v WHERE USERID = :u', {'v': True, 'u': user['ID']})
                return jsonify({'ok': True})
            return jsonify({'ok': False, 'error': 'invalid code'})
        else:
            return jsonify({'ok': False, 'error': 'no mfa'})
    else:
        return jsonify({'ok': False, 'error': 'bad/no authentication'})

@app.route('/api/forgotpass', methods=['POST'])
def api_forgotpass():
    email = request.form['email']
    user = db.run('SELECT ID, EMAIL_VERIFIED FROM users WHERE EMAIL = :e', {'e': email})
    if user == []:
        return jsonify({'error': 'no_user'})
    if not user[0]['EMAIL_VERIFIED']:
        return jsonify({'error': 'email_not_verified'})
    token = str(uuid4())
    repldb[token] = {'id': user[0]['ID'], 'time': time.time()}
    mjms.send_mail([email], 'Reset Password', html=f'<h1><a href="https://auth.marcusj.org/forgotpass/{token}">Click here to reset your password</a></h1><br><p>This link is only valid for 2 hours.</p>')
    return jsonify({'sent': True})

@app.route('/api/forgotpass/post', methods=['POST'])
def api_forgotpass_post():
    token = request.form['token']
    password = sha256(request.form['password'])
    userid = repldb.get(token, {}).get('id')
    if userid:
        if time.time() - repldb[token]['time'] > (60 * 60 * 2):
            del repldb[token]
            return jsonify({'changed': False})
        db.run('UPDATE users SET PASSHASH = :p WHERE ID = :i', {
            'p': password,
            'i': userid
        })
        del repldb[token]
        return jsonify({'changed': True})
    return jsonify({'changed': False})

@app.route('/api/email/check', methods=['POST'])
def api_email_check():
    user = api_auth()
    if user:
        if user['EMAIL_VERIFIED']:
            return jsonify({'verified': True})
        res = mjms.check_verified(user['EMAIL_TOKEN'])
        if res['verified']:
            db.run('UPDATE users SET EMAIL_VERIFIED = :e WHERE ID = :i AND EMAIL_TOKEN = :t', {
                'e': True, 
                'i': user['ID'], 
                't': user['EMAIL_TOKEN']
            })
        return jsonify(res)

@app.route('/api/email/resend', methods=['POST'])
def api_resend_email_check():
    user = api_auth()
    if user:
        if user['EMAIL_VERIFIED']:
            return jsonify({'verified': True})
        else:
            res = mjms.verify_email(user['EMAIL'])
            db.run('UPDATE users SET EMAIL_TOKEN = :t WHERE ID = :i', {'t': res['token'], 'i': user['ID']})
        return jsonify({'ok': True})
    return jsonify({'ok': False})

@app.route('/api/user', methods=['POST'])
def api_user():
    userdata = get_user.by_token(request.form['token'])
    clean = {k:v for k,v in userdata.items() if not k in ['PASSHASH', 'ID']}
    return jsonify({'user': clean})

@app.route('/api/auth', methods=['POST'])
def api_auth_route():
    user = api_auth()
    if user:
        domain = request.form['domain']
        token = register_token(user['ID'], domain)
        return jsonify(token)
    return jsonify({})

@app.route('/api/setsession', methods=['POST'])
def api_setsession():
    token = request.form['token']
    user = get_user.by_token(token)
    if user:
        session['user'] = user
        #return jsonify({'ok': True})
        return redirect(request.form.get('redirect', '/'))
    return jsonify({'error': 'invalid token'})

@app.route('/api/delete', methods=['POST'])
def api_delete():
    user = api_auth()
    if user:
        delete_user(user['ID'])
        return jsonify({'deleted': True})
    return jsonify({'deleted': False})

@app.route('/api/avatar/set', methods=['POST'])
def api_set_avatar():
    if (user := api_auth()):
        url = imj.upload(request.files['image'].read())
        set_avatar(user['USERNAME'], url)
        return jsonify({'updated': url})
    return jsonify({'updated': False})

# socket api
'''
@socketio.on('login')
def socket_login(json):
    return user_login(json['username'], json['password'])

@socketio.on('signup')
def socket_signup(json):
    username = json['username']
    if not valid_user(username):
        return {'error': 'invalid username'}
    user = register_user(username, json['password'], email=json.get('email'), fullname=json.get('fullname'))
    return user

@socketio.on('email_check')
def socket_email_check(json):
    user = get_user.by_token(json['token'])
    if user:
        if user['EMAIL_VERIFIED']:
            return {'verified': True}
        res = mjms.check_verified(user['EMAIL_TOKEN'])
        if res['verified']:
            db.run('UPDATE users SET EMAIL_VERIFIED = :e WHERE ID = :i AND EMAIL_TOKEN = :t', {
                'e': True, 
                'i': user['ID'], 
                't': user['EMAIL_TOKEN']
            })
        return res

@socketio.on('resend_email_check')
def socket_resend_email_check(json):
    user = get_user.by_token(json['token'])
    if user:
        if not user['EMAIL_VERIFIED']:
            res = mjms.verify_email(user['EMAIL'])
            db.run('UPDATE users SET EMAIL_TOKEN = :t WHERE ID = :i', {'t': res['token'], 'i': user['ID']})
        return {'ok': True}
    return {'ok': False}

@socketio.on('changepass')
def socket_change_pass(json):
    user = get_user.by_token(json['token'])
    if user:
        newpass = sha256(json['password'])
        db.run('UPDATE users SET PASSHASH = :p WHERE ID = :i', {
            'p': newpass,
            'i': user['ID'],
        })
        return {'changed': True}
    return {'changed': False}

@socketio.on('forgotpass post')
def socket_forgotpass_post(json):
    token = json['token']
    password = sha256(json['password'])
    userid = repldb.get(token, {}).get('id')
    if userid:
        if time.time() - repldb[token]['time'] > (60 * 60 * 2):
            del repldb[token]
            return {'changed': False}
        db.run('UPDATE users SET PASSHASH = :p WHERE ID = :i', {
            'p': password,
            'i': userid,
        })
        del repldb[token]
        return {'changed': True}
    return {'changed': False}

@socketio.on('forgotpass')
def socket_forgotpass(json):
    email = json['email']
    user = db.run('SELECT ID, EMAIL_VERIFIED FROM users WHERE EMAIL = :e', {'e': email})
    if user == []:
        return {'error': 'no_user'}
    if not user[0]['EMAIL_VERIFIED']:
        return {'error': 'email_not_verified'}
    token = str(uuid4())
    repldb[token] = {'id': user[0]['ID'], 'time': time.time()}
    mjms.send_mail([email], 'Reset Password', html=f'<h1><a href="https://auth.marcusj.org/forgotpass/{token}">Click here to reset your password</a></h1><br><p>This link is only valid for 2 hours.</p>')
    return {'sent': True}

@socketio.on('delete')
def socket_delete(json):
    user = get_user.by_token(json['token'])
    if user:
        delete_user(user['ID'])
        return {'deleted': True}
    return {'deleted': False}

@socketio.on('auth')
def socket_auth(json):
    user = get_user.by_token(json['token'])
    if user:
        domain = json['domain']
        token = register_token(user['ID'], domain)
        return token
    return {}

@socketio.on('user')
def socket_user(json):
    return get_user.by_token(json['token'])
'''

'''
if __name__ == '__main__':
    print('Starting app...')
    socketio.run(app=app, host='0.0.0.0', port=8080)
'''