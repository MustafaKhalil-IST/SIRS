import os
import ast
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from flask import Flask, abort, request, jsonify, g, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_httpauth import HTTPBasicAuth
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)
import json


def read_properties():
    props = {}
    f = open('../properties.conf')
    for line in f.readlines():
        props[line.split(":")[0]] = line.split(":")[1].replace('\n', '')
    f.close()
    return props

props = read_properties()
print(props)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'sirs is an interested subject'
# update this in your machine
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///./db.sqlite'
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True

db = SQLAlchemy(app)
auth = HTTPBasicAuth()


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), index=True)
    password_hash = db.Column(db.String(64))
    devices = db.relationship('Device', backref='users', lazy=True)

    def hash_password(self, password):
        # TODO use PyCrypto instead
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration=600):
        s = Serializer(app.config['SECRET_KEY'], expires_in=expiration)
        return s.dumps({'id': self.id})

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None
        except BadSignature:
            return None
        user = User.query.get(data['id'])
        return user


class Device(db.Model):
    __tablename__ = 'devices'
    id = db.Column(db.Integer, primary_key=True)
    mac_address = db.Column(db.String(48), index=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)


def json_of_device(device: Device):
    return {
        "id": device.id,
        "mac_address": device.mac_address,
        "owner_id": device.owner_id
    }


@auth.verify_password
def verify_password(username_or_token, password):
    user = User.verify_auth_token(username_or_token)
    if not user:
        user = User.query.filter_by(username=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True


@app.route('/auth/users', methods=['POST'])
def register_user():
    username = decrypt(ast.literal_eval(request.json.get('username')))
    password = decrypt(ast.literal_eval(request.json.get('password')))

    if username is None or password is None:
        abort(400)
    if User.query.filter_by(username=username).first() is not None:
        abort(400)
    user = User(username=username)
    user.hash_password(password)
    db.session.add(user)
    db.session.commit()
    return jsonify({'user_id': user.id}), 201


@app.route('/auth/users/login', methods=['POST'])
def login_user():
    username = decrypt(ast.literal_eval(request.json.get('username')))
    password = decrypt(ast.literal_eval(request.json.get('password')))
    device_mac_address = decrypt(ast.literal_eval(request.json.get('device_mac_address')))

    if username is None or password is None:
        abort(400)
    if User.query.filter_by(username=username).first() is None:
        abort(400)
    user = User.query.filter_by(username=username).first()
    login = verify_password(username, password)
    if login:
        device_id = None
        for device in user.devices:
            if device.mac_address == device_mac_address:
                device_id = device.id
        return jsonify({'user_id': user.id, 'device_id': device_id}), 201
    else:
        return jsonify({'message': "credentials are wrong"}), 401


@app.route('/auth/token', methods=['POST'])
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token(600)
    return jsonify({'token': token.decode('ascii'), 'duration': 600})


@app.route('/auth/users/<int:id>/devices', methods=['POST'])
@auth.login_required
def add_device(id):
    device_mac_address = decrypt(ast.literal_eval(request.json.get('device_mac_address')))
    user = User.query.get(id)
    if not user:
        abort(400)
    device = Device(mac_address=device_mac_address, owner_id=user.id)
    db.session.add(device)
    db.session.commit()
    return jsonify({'device_id': device.id})


@app.route('/auth/<int:id>/get_public_key', methods=['POST'])
@auth.login_required
def get_public_key(id):
    public_key = request.files['upload_file']
    public_key.save('keys/public_key_{}.pem'.format(id))
    return jsonify({'message': 'shared'})


@app.route('/auth/users/<int:id>/devices', methods=['GET'])
@auth.login_required
def get_user_devices(id):
    user = User.query.get(id)
    if not user:
        abort(400)
    msg = str(encrypt(str([json_of_device(device) for device in user.devices]), id=id))
    return jsonify({'devices': msg})


@app.route('/auth/check-authorization', methods=['POST'])
def check_authorization():
    LOCATION_SERVER = props['locations-server'] #"193.136.154.45" to be updated
    if request.remote_addr != LOCATION_SERVER:
        return jsonify({"message": "request is not authorized", 'is-authorized': False})

    data = request.json.get("data")
    username = decrypt(ast.literal_eval(data['username']))
    password = decrypt(ast.literal_eval(data['password']))

    return jsonify({'is-authorized': verify_password(username, password)})

def encrypt(message, id):
    data = message.encode("utf-8")

    recipient_key = RSA.import_key(open("keys/public_key_{}.pem".format(id)).read())
    session_key = get_random_bytes(16)

    # Encrypt the session key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    # Encrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)

    return (enc_session_key, cipher_aes.nonce, tag, ciphertext)


def decrypt(message):
    private_key = RSA.import_key(open("keys/private_key_AUTH-SERVER.pem").read())
    enc_session_key, nonce, tag, ciphertext = message

    # Decrypt the session key with the private RSA key
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    # Decrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    return data.decode("utf-8")


def generate_private_public_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    file_out = open("keys/private_key_AUTH-SERVER.pem", "wb")
    file_out.write(private_key)
    file_out.close()

    public_key = key.publickey().export_key()
    file_out = open("keys/public_key_AUTH-SERVER.pem", "wb")
    file_out.write(public_key)
    file_out.close()


if __name__ == '__main__':
    # generate_private_public_keys()
    db.create_all()
    app.run(host="193.136.154.45", port=8000)

