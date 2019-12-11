try:
    import bluetooth
except:
    pass

import requests
import ast
import random
from uuid import getnode
from requests.auth import HTTPBasicAuth
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
import threading
import time


def read_properties():
    props = {}
    f = open('../properties.conf')
    for line in f.readlines():
        props[line.split(":")[0]] = line.split(":")[1].replace('\n', '')
    f.close()
    return props


props = read_properties()


def bluetooth_point_reaction(client):
    try:
        client.receive_info_from_nearby_devices()
    except:
        print("Bluetooth is not connected")


def periodic_location_update(client):
    while True:
        if client.LOGGEDIN and client.IS_MY_DEVICE:
            client.update_my_location()
        time.sleep(60)


def periodic_keys_update(client):
    while True:
        if client.LOGGEDIN:
            client.generate_private_public_keys()
            client.share_public_key()
        time.sleep(60 * 60 * 24) # daily


class ClientApp:
    AUTH_SERVER_URL = "http://{}:8000/auth".format(props['auth-server'])
    LOCATIONS_SERVER_URL = "http://{}:8001/locations".format(props['locations-server'])
    LOGGEDIN = False
    IS_MY_DEVICE = False
    USERNAME, PASSWORD, USER_ID, DEVICE_ID, TOKEN, MAC_ADDRESS = None, None, None, None, None, None

    """User Interface"""
    def register_user(self, username, password):
        #self.generate_private_public_keys()
        data = {
            "username": username,
            "password": password
        }

        # encrypt data
        encrypted_data = {
            "data": str(self.encrypt(str(data)))
        }

        r = requests.post(url=self.AUTH_SERVER_URL + '/users', json=encrypted_data)

        if r.status_code == 201 or r.status_code == 200:
            # WRONG
            # self.login(username, password)
            # self.share_public_key()
            print("Registeration: User Registered")
        elif r.status_code == 400:
            print(r.json()['error'])

    def login(self, username, password):
        data = {
            "username": username,
            "password": password,
            "device_mac_address": str(getnode())
        }

        # encrypt data
        encrypted_data = {
            "data": str(self.encrypt(str(data))),
        }

        r = requests.post(url=self.AUTH_SERVER_URL + '/users/login', json=encrypted_data)
        if r.status_code == 201 or r.status_code == 200:
            self.USERNAME = username
            self.PASSWORD = password
            self.MAC_ADDRESS = str(getnode())
            self.DEVICE_ID = r.json()['device_id']
            self.USER_ID = r.json()['user_id']
            self.LOGGEDIN = True
            self.IS_MY_DEVICE = self.check_is_my_device()
            return 1
        else:
            if 'message' in r.json():
                print(r.json()['message'])
            return 0

    def check_is_my_device(self):
        auth = HTTPBasicAuth(self.USERNAME, self.PASSWORD)

        device_mac_address = str(getnode())
        # encrypt data
        data = {
            "device_mac_address": device_mac_address
        }

        encrypted_data = {
            'data': str(self.encrypt(str(data)))
        }
        r = requests.post(url=self.AUTH_SERVER_URL + '/users/' + str(self.USER_ID) + '/devices/is_my_device',
                          json=encrypted_data, auth=auth)

        return r.json()['is_my_device']

    def add_this_device(self):
        if not self.LOGGEDIN:
            print("[Error]: You are not logged in")
            return

        device_mac_address = str(getnode())
        # encrypt data
        data = {
            "device_mac_address": device_mac_address
        }

        encrypted_data = {
            'data': str(self.encrypt(str(data)))
        }

        auth = HTTPBasicAuth(self.USERNAME, self.PASSWORD)
        r = requests.post(url=self.AUTH_SERVER_URL + '/users/' + str(self.USER_ID) + '/devices',
                          json=encrypted_data, auth=auth)
        if r.status_code == 200:
            self.DEVICE_ID = r.json()['device_id']
            self.MAC_ADDRESS = device_mac_address
            self.IS_MY_DEVICE = True
            self.generate_private_public_keys()
            self.share_public_key()
            print("Add Device: {}".format(r.json()['message']))

    def check_my_devices_location(self):
        if not self.LOGGEDIN:
            print("[Error]: You are not logged in")
            return

        if not self.IS_MY_DEVICE:
            # TODO cases
            print("You are not allowed to see your devices locations in this device")
            return

        auth = HTTPBasicAuth(self.USERNAME, self.PASSWORD)
        r_auth = requests.get(self.AUTH_SERVER_URL + '/users/{}/devices'.format(self.USER_ID), auth=auth)

        devices = ast.literal_eval(self.decrypt(ast.literal_eval(r_auth.json()['response'])))

        print('Locations: ')
        for dev in devices:
            r_loc = requests.get(self.LOCATIONS_SERVER_URL + '/{}/locate/{}'.format(self.USER_ID, dev['id']))
            response = self.decrypt(ast.literal_eval(r_loc.json()['response']))
            print('Device {} was last seen in location {}'.format(dev['id'], response))

    """Devices Interface"""
    def get_device_loation(self):
        # just a random thing, to prove a concept
        return (random.random() * 120, random.random() * 120)

    def is_server_reachable(self):
        try:
            # requests.get("https://www.google.com", timeout=10)
            requests.get('http://{}:8001/locations/alive'.format(props['locations-server']), timeout=10)
            requests.get('http://{}:8000/auth/alive'.format(props['auth-server']), timeout=10)
            return True
        except:
            return False

    def remove_device(self, dev_id):
        if not self.LOGGEDIN:
            print("[Error]: You are not logged in")
            return

        auth = HTTPBasicAuth(self.USERNAME, self.PASSWORD)
        data = {
            'device_id': dev_id
        }

        encrypted_data = {
            'data': str(self.encrypt(str(data)))
        }

        r = requests.post(self.AUTH_SERVER_URL + '/users/{}/devices/remove-device'.format(self.USER_ID),
                            json=encrypted_data, auth=auth)
        print(r.json()['message'])

    def update_my_location(self):
        if not self.LOGGEDIN:
            print("[Error]: You are not logged in")
            return

        # check_is_my_decice()
        if not self.IS_MY_DEVICE:
            print("This device is not owned by you")
            return

        auth = HTTPBasicAuth(self.USERNAME, self.PASSWORD)
        location = self.get_device_loation()

        # encrypt data
        data = {
            'location': location,
            'mac_address': self.MAC_ADDRESS
        }

        encrypted_data = {
            'data': str(self.encrypt(str(data), id="LOCATIONS-SERVER"))
        }

        if self.DEVICE_ID is None:
            print("This device is not recognized")
            return

        if self.is_server_reachable():
            r_loc = requests.post(self.LOCATIONS_SERVER_URL + '/{}/locate/{}'.format(self.USER_ID, self.DEVICE_ID),
                                  json=encrypted_data, auth=auth)
            if r_loc.status_code == 200:
                print("Location update: Done")
            else:
                if 'message' in r_loc.json():
                    print(r_loc.json()['message'])
                print("Location update: Failed")
        else:
            self.send_info_to_nearby_devices()

    def scan_nearby_devices(self):
        devices = bluetooth.discover_devices()
        addrs = []
        for addr, _ in devices:
            addrs.append(addr)
        return addrs

    def send_info_to_nearby_devices(self):
        if self.DEVICE_ID is None:
            print("This device is not recognized")
            return

        data = {
            'user_id': self.USER_ID,
            'device_id': self.DEVICE_ID,
            'location': self.get_device_loation()
        }

        encrypted_data = {
            'data': str(self.encrypt(str(data), id='LOCATIONS-SERVER')),
        }

        addrs = self.scan_nearby_devices()

        sock = bluetooth.BluetoothSocket(bluetooth.L2CAP)
        port = 4  # the app bluetooth port is 4
        for addr in addrs:
            try:
                sock.connect((addr, port))
                sock.send(str(encrypted_data))
            except:
                pass

    def receive_info_from_nearby_devices(self):
        #TODO still not very clear
        sock = bluetooth.BluetoothSocket(bluetooth.L2CAP)
        port = 4# the app bluetooth port is 4
        sock.connect(("", port))

        received = sock.recv(1024)
        if self.is_server_reachable():
            self.redirect_data_to_server(received)

    def redirect_data_to_server(self, data):
        auth = HTTPBasicAuth(self.USERNAME, self.PASSWORD)
        requests.post(self.LOCATIONS_SERVER_URL + '/get-redirected-info', json=data, auth=auth)

    def generate_private_public_keys(self):
        key = RSA.generate(2048)
        private_key = key.export_key()
        file_out = open("keys/private.pem", "wb")
        file_out.write(private_key)
        file_out.close()

        public_key = key.publickey().export_key()
        file_out = open("keys/public.pem", "wb")
        file_out.write(public_key)
        file_out.close()

    def share_public_key(self):
        auth = HTTPBasicAuth(self.USERNAME, self.PASSWORD)
        pk = open('keys/public.pem', 'r')
        files = {'upload_file': pk}
        requests.post(self.AUTH_SERVER_URL + '/{}/get_public_key'.format(self.DEVICE_ID), files=files, auth=auth)
        pk.close()

        pk = open('keys/public.pem', 'r')
        files = {'upload_file': pk}
        requests.post(self.LOCATIONS_SERVER_URL + '/{}/get_public_key'.format(self.DEVICE_ID), files=files, auth=auth)
        pk.close()

    def encrypt(self, message, id='AUTH-SERVER'):
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

    def decrypt(self, message):
        private_key = RSA.import_key(open("keys/private.pem").read())

        enc_session_key, nonce, tag, ciphertext = message

        # Decrypt the session key with the private RSA key
        cipher_rsa = PKCS1_OAEP.new(private_key)
        session_key = cipher_rsa.decrypt(enc_session_key)

        # Decrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        data = cipher_aes.decrypt_and_verify(ciphertext, tag)
        return data.decode("utf-8")


client = ClientApp()

bluetooth_point = threading.Thread(target=bluetooth_point_reaction, args=(client,))
bluetooth_point.start()
periodic_update = threading.Thread(target=periodic_location_update, args=(client,))
periodic_update.start()
keys_update = threading.Thread(target=periodic_keys_update, args=(client,))
keys_update.start()

options = ["login", "register", "add device", "update device location", "check devices locations", "remove device"]
while True:
    print("Select a number:")
    for i, option in enumerate(options):
        print('{}-  {}'.format(i, option))
    command = int(input('select: '))
    if command == options.index("login"):
        res = 0
        if res == 0:
            username = input("username: ")
            password = input("password: ")
            res = client.login(username, password)
            if res == 0:
                print("Credentials are wrong, try again")
            else:
                print("You are logged in")
    elif command == options.index("register"):
        username = input("username: ")
        password = input("password: ")
        client.register_user(username, password)
    elif command == options.index("add device"):
        client.add_this_device()
    elif command == options.index("update device location"):
        client.update_my_location()
    elif command == options.index("check devices locations"):
        client.check_my_devices_location()
    elif command == options.index("remove device"):
        dev_id = int(input('Enter device id to remove: '))
        client.remove_device(dev_id)
