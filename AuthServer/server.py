import ast
from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from flask import Flask, abort, request, jsonify, g, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_httpauth import HTTPBasicAuth
from Cryptodome.Hash import SHA256
from passlib.apps import custom_app_context as pwd_context
import hashlib
import binascii
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)
import os


def read_properties():
    props = {}
    f = open('../properties.conf')
    for line in f.readlines():
        props[line.split(":")[0]] = line.split(":")[1].replace('\n', '')
    f.close()
    return props


props = read_properties()
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
    nr_tries = db.Column(db.Integer)

    def hash_password(self, password):
        salt = hashlib.sha256(os.urandom(60)).hexdigest().encode('ascii')
        pwdhash = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'),
                                      salt, 100000)
        pwdhash = binascii.hexlify(pwdhash)
        self.password_hash = (salt + pwdhash).decode('ascii')

    def verify_password(self, provided_password):
        salt = self.password_hash[:64]
        password = self.password_hash[64:]
        pwdhash = hashlib.pbkdf2_hmac('sha512',
                                      provided_password.encode('utf-8'),
                                      salt.encode('ascii'),
                                      100000)
        pwdhash = binascii.hexlify(pwdhash).decode('ascii')
        return pwdhash == password

    def hash_password_obsolete(self, password):
        self.password_hash = hashlib.sha3_256(password.encode()) #SHA256.new(password.encode())

    def verify_password_obsolete(self, password):
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
    blocked = db.Column(db.Boolean, default=False)


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


def validate_password(password):
    if len(password) < 9:
        return False
    if not any(char.isdigit() for char in password):
        return False
    if not any(char.isupper() for char in password):
        return False
    if not any(char.islower() for char in password):
        return False
    return True


@app.route('/auth/users', methods=['POST'])
def register_user():
    data = ast.literal_eval(decrypt(ast.literal_eval(request.json.get('data'))))

    username = data.get('username')
    password = data.get('password')

    if not validate_password(password):
        return jsonify({'error': 'password must have 9 or more chars, at least one upper, one lower and one digit'}), 400
    if username is None or password is None:
        return jsonify({'error': 'credentials are not correct'}), 400
    if User.query.filter_by(username=username).first() is not None:
        return jsonify({'error': 'the user {} already exits'.format(username)}), 400

    user = User(username=username, nr_tries=0)
    user.hash_password(password)
    db.session.add(user)
    db.session.commit()
    return jsonify({'user_id': user.id}), 201


@app.route('/auth/alive', methods=['GET'])
def i_am_alive():
    return jsonify({'message': 'I am Alive'})


@app.route('/auth/users/<id>/devices/remove-device', methods=['POST'])
@auth.login_required
def remove_device(id):
    user = User.query.filter_by(id=id).first()
    data = ast.literal_eval(decrypt(ast.literal_eval(request.json['data'])))
    device_id = int(data['device_id'])

    if Device.query.filter_by(id=device_id).first() is None:
        return jsonify({'message': 'this device deos not exits'}), 404

    if device_id not in [dev.id for dev in user.devices]:
        return jsonify({'message': 'this device does not belong to user'}), 401

    Device.query.filter_by(id=device_id).delete()
    db.session.commit()

    # return jsonify({'message': 'error'}), 400
    return jsonify({'message': 'done'}), 200


@app.route('/auth/users/login', methods=['POST'])
def login_user():
    data = ast.literal_eval(decrypt(ast.literal_eval(request.json.get('data'))))
    username = data.get('username')
    password = data.get('password')
    device_mac_address = data.get('device_mac_address')

    device = Device.query.filter_by(mac_address=device_mac_address).first()

    if device is not None and device.blocked:
        return jsonify({'message': 'this device is blocked'}), 400
    if username is None or password is None:
        return jsonify({'message': 'username or password is missing'}), 400
    if User.query.filter_by(username=username).first() is None:
        return jsonify({'message': 'the user {} does not exits'.format(username)}), 400
    user = User.query.filter_by(username=username).first()
    login = verify_password(username, password)

    if login:
        user.nr_tries = 0
        db.session.commit()
        device_id = None

        is_my_device = True
        if device is not None:
            if device.owner_id != user.id:
                is_my_device = False

            device_id = device.id

        return jsonify({'user_id': user.id, 'device_id': device_id, 'is_my_device': is_my_device}), 201
    else:
        user.nr_tries += 1
        db.session.commit()

        if user.nr_tries == 3:
            device = Device.query.filter_by(mac_address=device_mac_address).first()
            if device is not None:
                device.blocked = True
                db.session.commit()

        return jsonify({'message': "credentials are wrong"}), 401


@app.route('/auth/token', methods=['POST'])
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token(600)
    return jsonify({'token': token.decode('ascii'), 'duration': 600})


@app.route('/auth/users/<int:id>/devices', methods=['POST'])
@auth.login_required
def add_device(id):
    data = ast.literal_eval(decrypt(ast.literal_eval(request.json.get('data'))))
    device_mac_address = data['device_mac_address']
    user = User.query.get(id)
    if not user:
        abort(400)
    device = Device.query.filter_by(mac_address=device_mac_address).first()
    if device is not None:
        if device.owner_id == id:
            return jsonify({'device_id': device.id, 'message': 'this device is already added'})
        else:
            return jsonify({'device_id': device.id, 'message': 'this device does not belong to the user'})
    device = Device(mac_address=device_mac_address, owner_id=user.id)
    db.session.add(device)
    db.session.commit()
    return jsonify({'device_id': device.id, 'message': 'the device is added'})


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
    return jsonify({'response': msg})


@app.route('/auth/check-ownership', methods=['POST'])
def check_ownership():
    LOCATION_SERVER = props['locations-server'] #"193.136.154.45" to be updated
    if request.remote_addr != LOCATION_SERVER:
        return jsonify({"message": "request is not authorized", 'is-owner': False})

    data = ast.literal_eval(decrypt(ast.literal_eval(request.json["data"])))
    user_id = data['user_id']
    device_id = data['device_id']

    user = User.query.filter_by(id=user_id).first()

    #TODO add encryption
    if user is not None:
        is_owner = False
        for dev in user.devices:
            if dev.id == int(device_id):
                is_owner = True
                break
        return jsonify({'is-owner': is_owner})

    return jsonify({'is-owner': False})


@app.route('/auth/check-authorization', methods=['POST'])
def check_authorization():
    LOCATION_SERVER = props['locations-server']
    if request.remote_addr != LOCATION_SERVER:
        return jsonify({"message": "request is not authorized", 'is-authorized': False})

    data = ast.literal_eval(decrypt(ast.literal_eval(request.json['data'])))
    username = data['username']
    password = data['password']

    # TODO encryption
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
    app.run(host=props['auth-server'], port=8000)

