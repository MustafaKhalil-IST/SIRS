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

POSTGRES_URL = get_env_variable("POSTGRES_URL")
POSTGRES_USER = get_env_variable("POSTGRES_USER")
POSTGRES_PW = get_env_variable("POSTGRES_PW")
POSTGRES_DB = get_env_variable("POSTGRES_DB")

DB_URL = 'postgresql+psycopg2://{user}:{pw}@{url}/{db}'.format(user=POSTGRES_USER, pw=POSTGRES_PW, url=POSTGRES_URL,
                                                               db=POSTGRES_DB)

app.config['SQLALCHEMY_DATABASE_URI'] = DB_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # silence the deprecation warning

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


@app.route('/locations/<dev>', methods=['GET'])
def get_location(dev):
    location = db.session.query(Location.location).filter_by(devices_id=dev).order_by(Location.timestamp.desc()).first()

    if not location:
        return jsonify({'message': 'No location information!'})

    return jsonify({'location': location})


@app.route('/locations', methods=['POST'])
def set_location():
    data = request.get_json()  # must receive json with deviceID, macAddress, location

    devicecheck = db.session.query(Devices).filter(Devices.deviceID == data['dev']).one_or_none()
    if devicecheck is None:
        new_Device = Devices(deviceID=data['dev'], macAddress=data['macAddress'])
        db.session.add(new_Device)
        db.session.commit()

    new_location = Location(devices_id=data['dev'], location=data['location'])
    db.session.add(new_location)
    db.session.commit()

    return jsonify({'message': 'New location successfully added!'})

@app.route('/locations', methods=['PUT']) #must receive json with deviceID, macAddress
def refresh_Mac_Address():
    data = request.get_json()
    mac_refresh = db.session.query(Devices.deviceID).filter(Devices.deviceID == data['dev']).update({"macAddress" : data['macAddress']})
    db.session.commit()
    return jsonify({'message' : 'action done'})


if __name__ == '__main__':
    app.run(debug=True)
