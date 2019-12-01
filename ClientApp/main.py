# importing the requests library 
import requests
import ast
from requests.auth import HTTPBasicAuth
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES, PKCS1_OAEP


# TODO add logging, bluetooth, clients intercommunication, share public key
class ClientApp:
    AUTH_SERVER_URL = "http://127.0.0.1:8000/auth"
    LOCATIONS_SERVER_URL = "http://127.0.0.1:8001/locations"
    USERNAME, PASSWORD, USER_ID, DEVICE_ID, TOKEN, MAC_ADDRESS = None, None, None, None, None, None

    """User Interface"""
    def register_user(self, username, password):
        # encrypt data
        encrypted_data = {
            "username": str(self.encrypt(username)),
            "password": str(self.encrypt(password))
        }

        r = requests.post(url=self.AUTH_SERVER_URL + '/users', json=encrypted_data)

        if r.status_code == 201 or r.status_code == 200:
            print("User Registered")
        else:
            print("Something wrong")

    def login(self, username, password):
        # encrypt data
        encrypted_data = {
            "username": str(self.encrypt(username)),
            "password": str(self.encrypt(password))
        }

        r = requests.post(url=self.AUTH_SERVER_URL + '/users/login', json=encrypted_data)
        if r.status_code == 201 or r.status_code == 200:
            self.USERNAME = username
            self.PASSWORD = password
            self.USER_ID = r.json()['user_id']


    def refresh_token(self, username, password):
        # TODO not quite clear how to use
        headers = {
            "username": username,
            "password": password
        }
        r = requests.post(self.AUTH_SERVER_URL + '/token', auth=headers)
        print(r.status_code)

    def add_this_device(self, device_mac_address):
        data = {
            "device_mac_address": device_mac_address,
        }

        # encrypt data
        encrypted_data = {
            "device_mac_address": str(self.encrypt(device_mac_address))
        }

        auth = HTTPBasicAuth(self.USERNAME, self.PASSWORD)
        r = requests.post(url=self.AUTH_SERVER_URL + '/users/' + str(self.USER_ID) + '/devices',
                          json=encrypted_data, auth=auth)
        if r.status_code == 200:
            self.DEVICE_ID = r.json()['device_id']
            self.MAC_ADDRESS = device_mac_address
            # print(r.json())

    def check_my_devices_location(self):
        auth = HTTPBasicAuth(self.USERNAME, self.PASSWORD)
        r_auth = requests.get(self.AUTH_SERVER_URL + '/users/{}/devices'.format(self.USER_ID), auth=auth)

        devices = ast.literal_eval(self.decrypt(ast.literal_eval(r_auth.json()['devices'])))

        for dev in devices:
            r_loc = requests.get(self.LOCATIONS_SERVER_URL + '/{}'.format(dev['id']))
            print(r_loc.json())

        #return locations

    """Devices Interface"""
    def is_server_reachable(self):
        try:
            # TODO substitute with server url
            requests.get('https://www.google.com/', timeout=2)
            return True
        except:
            return False

    def update_my_location(self):
        import random
        location = (random.random() * 120, random.random() * 120)

        # encrypt data
        encrypted_data = {
            'location': str(self.encrypt(str(location))),
            'mac_address': str(self.encrypt(self.MAC_ADDRESS))
        }

        r_loc = requests.post(self.LOCATIONS_SERVER_URL + '/{}'.format(self.DEVICE_ID), json=encrypted_data)

        if r_loc.status_code != 200:
            print("Something is wrong")
        else:
            print("Done")

    def receive_info_from_nearby_devices(self):
        pass

    def scan_nearby_devices(self):
        pass

    def generate_private_public_keys(self):
        key = RSA.generate(2048)
        private_key = key.export_key()
        file_out = open("keys\\private.pem", "wb")
        file_out.write(private_key)
        file_out.close()

        public_key = key.publickey().export_key()
        file_out = open("keys\\public.pem", "wb")
        file_out.write(public_key)
        file_out.close()

    def share_public_key(self):
        auth = HTTPBasicAuth(self.USERNAME, self.PASSWORD)
        files = {'upload_file': open('keys\\public.pem', 'r')}
        r = requests.post(self.AUTH_SERVER_URL + '/{}/get_public_key'.format(self.USER_ID), files=files, auth=auth)

        if r.status_code != 200:
            pass

    def encrypt(self, message):
        data = message.encode("utf-8")

        recipient_key = RSA.import_key(open("keys\\server_public.pem").read())
        session_key = get_random_bytes(16)

        # Encrypt the session key with the public RSA key
        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        enc_session_key = cipher_rsa.encrypt(session_key)

        # Encrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(data)
        return (enc_session_key, cipher_aes.nonce, tag, ciphertext)

    def decrypt(self, message):
        private_key = RSA.import_key(open("keys\\private.pem").read())

        enc_session_key, nonce, tag, ciphertext = message

        # Decrypt the session key with the private RSA key
        cipher_rsa = PKCS1_OAEP.new(private_key)
        session_key = cipher_rsa.decrypt(enc_session_key)

        # Decrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        data = cipher_aes.decrypt_and_verify(ciphertext, tag)
        return data.decode("utf-8")


"""
client = ClientApp()
print(client.internet_on())
# client.register_user("mustafa_6", "1291241241")
client.login("mustafa_6", "1291241241")

client.add_this_device("ASFA42DWF3")
client.update_my_location()

client.check_my_devices_location()
"""

client = ClientApp()
#client.register_user("mustafa_7", "1291241241")
client.login("mustafa_6", "1291241241")
client.add_this_device("ASFA42DWF3")
client.update_my_location()
client.check_my_devices_location()

# client.share_public_key()
# client.add_this_device("ASFA42DWF3")
# client.update_my_location()
# locs = client.check_my_devices_location()
# print(locs)
