from flask import Flask
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

POSTGRES_URL =get_env_variable("POSTGRES_URL")
POSTGRES_USER =get_env_variable("POSTGRES_USER")
POSTGRES_PW =get_env_variable("POSTGRES_PW")
POSTGRES_DB =get_env_variable("POSTGRES_DB")

DB_URL = 'postgresql+psycopg2://{user}:{pw}@{url}/{db}'.format(user=POSTGRES_USER, pw=POSTGRES_PW, url=POSTGRES_URL, db=POSTGRES_DB)


app.config['SQLALCHEMY_DATABASE_URI'] = DB_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False   # silence the deprecation warning

db = SQLAlchemy(app)


class Devices(db.Model):
    deviceID = db.Column(db.Integer, primary_key=True)
    macAddress = db.Column(db.String(20))
    location = db.relationship('Location', backref='devices', lazy=True)

class Location(db.Model):
    locationID = db.Column(db.Integer,primary_key=True)
    divTableID = db.Column(db.Integer, db.ForeignKey('devices.deviceID'), nullable=False)
    location = db.Column(db.String(20), unique=False, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


@app.route('/locations/address', methods=['GET'])
def get_location():
    return''

@app.route('/locations', method=['POST'])
def set_location():
    return''

if __name__ == '__main__':
    app.run(debug=True)


