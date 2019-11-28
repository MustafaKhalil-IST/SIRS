import os
from flask import Flask, abort, request, jsonify, g, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_httpauth import HTTPBasicAuth
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)
import json

app = Flask(__name__)
app.config['SECRET_KEY'] = 'sirs is an interested subject'
# update this in your machine
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///C:\\Users\\cash\\MEIC\\SIRS\\SIRS\\Project\\AuthServer\\db.sqlite'
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


@app.route('/api/users', methods=['POST'])
def register_user():
    username = request.json.get('username')
    password = request.json.get('password')
    if username is None or password is None:
        abort(400)
    if User.query.filter_by(username=username).first() is not None:
        abort(400)
    user = User(username=username)
    user.hash_password(password)
    db.session.add(user)
    db.session.commit()
    return jsonify({'username': user.username}), 201


@app.route('/api/users', methods=['GET'])
def all_users():
    users = User.query.all()
    print(users)
    return jsonify({'users': 'done'}), 201


@app.route('/api/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token(600)
    return jsonify({'token': token.decode('ascii'), 'duration': 600})


@app.route('/api/users/<int:id>/devices', methods=['POST'])
@auth.login_required
def add_device(id):
    device_mac_address = request.json.get('device_mac_address')
    user = User.query.get(id)
    if not user:
        abort(400)
    device = Device(mac_address=device_mac_address, owner_id=user.id)
    db.session.add(device)
    db.session.commit()
    return jsonify({'message': 'success'})


@app.route('/api/users/<int:id>/devices', methods=['GET'])
@auth.login_required
def get_user_devices(id):
    user = User.query.get(id)
    if not user:
        abort(400)

    return jsonify({'devices': [json_of_device(device) for device in user.devices]})


if __name__ == '__main__':
    db.create_all()
    app.run(port=8000)

