from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
import os
from datetime import datetime
import requests
import ast

app = Flask(__name__)

"""
# the values of those depend on environment variables
def get_env_variable(name):
    try:
        return os.environ[name]
    except KeyError:
        message = "Expected environment variable '{}' not set.".format(name)
        raise Exception(message)

POSTGRES_URL = get_env_variable("POSTGRES_URL")
POSTGRES_USER = get_env_variable("POSTGRES_USER")
POSTGRES_PW = get_env_variable("POSTGRES_PW")
POSTGRES_DB = get_env_variable("POSTGRES_DB")

DB_URL = 'postgresql+psycopg2://{user}:{pw}@{url}/{db}'.format(user=POSTGRES_USER, pw=POSTGRES_PW, url=POSTGRES_URL,
                                                               db=POSTGRES_DB)

app.config['SQLALCHEMY_DATABASE_URI'] = DB_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # silence the deprecation warning
"""

app.config['SECRET_KEY'] = 'sirs is very interested subject'
# update this in your machine
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///C:\\Users\\cash\\MEIC\\SIRS\\SIRS\\Project\\LocationsServer\\db.sqlite'
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
db = SQLAlchemy(app)


class Devices(db.Model):
    deviceID = db.Column(db.Integer, primary_key=True)
    macAddress = db.Column(db.String(20))
    location = db.relationship('Location', backref='foreign_device', lazy=True)


class Location(db.Model):
    locationID = db.Column(db.Integer, primary_key=True)
    location = db.Column(db.String(20), unique=False, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    devices_id = db.Column(db.Integer, db.ForeignKey('devices.deviceID'))


def check_authorization(username, password):
    encrypted_data = {
        "username": str(encrypt(username, "AUTH-SERVER")),
        "password": str(encrypt(password, "AUTH-SERVER"))
    }

    data = {
        "data": encrypted_data
    }

    AUTH_SERVER_URL = "http://127.0.0.1:8000/auth"

    r = requests.post(AUTH_SERVER_URL + '/check-authorization', json=data)

    return r.json()['is-authorized']

# TODO add encryption
@app.route('/locations/<id>/locate/<dev>', methods=['GET'])
def get_location(id, dev):
    location = db.session.query(Location.location).filter_by(devices_id=dev).order_by(Location.timestamp.desc()).first()
    location = location[0]

    if not location:
        return jsonify({'message': 'No location information!'})

    location = encrypt(location, id)

    return jsonify({'location': str(location)})


@app.route('/locations/<id>/locate/<dev>', methods=['POST'])
def set_location(id, dev):
    auth = request.authorization

    username = auth['username']
    password = auth['password']

    if check_authorization(username=username, password=password):
        data = request.get_json()  # must receive json with macAddress, location
        device_check = db.session.query(Devices).filter(Devices.deviceID == dev).one_or_none()
        if device_check is None:
            mac_address = decrypt(ast.literal_eval(data.get('mac_address')))
            new_Device = Devices(deviceID=dev, macAddress=mac_address)
            db.session.add(new_Device)
            db.session.commit()

        location = decrypt(ast.literal_eval(data.get('location')))
        new_location = Location(devices_id=dev, location=location)
        db.session.add(new_location)
        db.session.commit()

        return jsonify({'message': 'New location successfully added!'})


@app.route('/locations', methods=['PUT']) #must receive json with deviceID, macAddress
def refresh_Mac_Address():
    data = request.get_json()

    mac_address = decrypt(ast.literal_eval(data.get('macAddress')))
    dev = decrypt(ast.literal_eval(data.get('dev')))

    db.session.query(Devices.deviceID).filter(Devices.deviceID == dev).update({"macAddress": mac_address})
    db.session.commit()
    return jsonify({'message': 'action done'})


@app.route('/locations/<int:id>/get_public_key', methods=['POST'])
def get_public_key(id):
    auth = request.authorization

    username = auth['username']
    password = auth['password']

    if check_authorization(username, password):
        public_key = request.files['upload_file']
        public_key.save('keys\\public_key_{}.pem'.format(id))
        return jsonify({'message': 'shared'})
    else:
        return jsonify({'message': 'unauthorized'})


def encrypt(message, id):
    data = message.encode("utf-8")

    recipient_key = RSA.import_key(open("keys\\public_key_{}.pem".format(id)).read())
    session_key = get_random_bytes(16)

    # Encrypt the session key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    # Encrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)

    return (enc_session_key, cipher_aes.nonce, tag, ciphertext)


def decrypt(message):
    private_key = RSA.import_key(open("keys\\private_key_LOCATIONS-SERVER.pem").read())
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
    file_out = open("keys\\private_key_LOCATIONS-SERVER.pem", "wb")
    file_out.write(private_key)
    file_out.close()

    public_key = key.publickey().export_key()
    file_out = open("keys\\public_key_LOCATIONS-SERVER.pem", "wb")
    file_out.write(public_key)
    file_out.close()


if __name__ == '__main__':
    db.create_all()
    app.run(debug=True, port=8001)
