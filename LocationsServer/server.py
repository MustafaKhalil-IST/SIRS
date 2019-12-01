from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
import os
from datetime import datetime

app = Flask(__name__)


def get_env_variable(name):
    try:
        return os.environ[name]
    except KeyError:
        message = "Expected environment variable '{}' not set.".format(name)
        raise Exception(message)


# the values of those depend on environment variables
"""
POSTGRES_URL = get_env_variable("POSTGRES_URL")
POSTGRES_USER = get_env_variable("POSTGRES_USER")
POSTGRES_PW = get_env_variable("POSTGRES_PW")
POSTGRES_DB = get_env_variable("POSTGRES_DB")

DB_URL = 'postgresql+psycopg2://{user}:{pw}@{url}/{db}'.format(user=POSTGRES_USER, pw=POSTGRES_PW, url=POSTGRES_URL,
                                                               db=POSTGRES_DB)

app.config['SQLALCHEMY_DATABASE_URI'] = DB_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # silence the deprecation warning
"""

app.config['SECRET_KEY'] = 'sirs is an so interested subject'
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
    # TODO call auth server to check authorization
    # TODO add encryption
    pass

# TODO add encryption
@app.route('/locations/<dev>', methods=['GET'])
def get_location(dev):
    location = db.session.query(Location.location).filter_by(devices_id=dev).order_by(Location.timestamp.desc()).first()

    if not location:
        return jsonify({'message': 'No location information!'})

    return jsonify({'location': location})

# TODO add decryption
@app.route('/locations/<dev>', methods=['POST'])
def set_location(dev):
    data = request.json()  # must receive json with macAddress, location
    device_check = db.session.query(Devices).filter(Devices.deviceID == dev).one_or_none()
    if device_check is None:
        new_Device = Devices(deviceID=dev, macAddress=data['mac_address'])
        db.session.add(new_Device)
        db.session.commit()

    new_location = Location(devices_id=dev, location=data['location'])
    db.session.add(new_location)
    db.session.commit()

    return jsonify({'message': 'New location successfully added!'})

# TODO add decryption
@app.route('/locations', methods=['PUT']) #must receive json with deviceID, macAddress
def refresh_Mac_Address():
    data = request.get_json()
    db.session.query(Devices.deviceID).filter(Devices.deviceID == data['dev']).update({"macAddress": data['macAddress']})
    db.session.commit()
    return jsonify({'message': 'action done'})


# TODO must be done after checking authorization by calling auth server
@app.route('/locations/<int:id>/get_public_key', methods=['POST'])
def get_public_key(id):
    public_key = request.files['upload_file']
    public_key.save('keys\\public_key_{}.pem'.format(id))
    return jsonify({'message': 'shared'})


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
    private_key = RSA.import_key(open("keys\\server_private.pem").read())
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
    file_out = open("keys\\locations_server_private.pem", "wb")
    file_out.write(private_key)
    file_out.close()

    public_key = key.publickey().export_key()
    file_out = open("keys\\locations_public.pem", "wb")
    file_out.write(public_key)
    file_out.close()


if __name__ == '__main__':
    db.create_all()
    app.run(debug=True, port=8001)
