# importing the requests library 
import requests
from requests.auth import HTTPBasicAuth


class ClientApp:
    AUTH_SERVER_URL = "http://127.0.0.1:8000/auth"
    LOCATIONS_SERVER_URL = "http://127.0.0.1:8001/locations"
    USERNAME, PASSWORD, USER_ID, DEVICE_ID, TOKEN, MAC_ADDRESS = None, None, None, None, None, None

    """User Interface"""
    def register_user(self, username, password):
        data = {
            "username": username,
            "password": password
        }
        r = requests.post(url=self.AUTH_SERVER_URL + '/users', json=data)
        if r.status_code == 201 or r.status_code == 200:
            self.USERNAME = username
            self.PASSWORD = password
            self.USER_ID = r.json()['user_id']
            print(r.json())

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
        auth = HTTPBasicAuth(self.USERNAME, self.PASSWORD)
        r = requests.post(url=self.AUTH_SERVER_URL + '/users/' + str(self.USER_ID) + '/devices', json=data, auth=auth)
        if r.status_code == 200:
            self.DEVICE_ID = r.json()['device_id']
            self.MAC_ADDRESS = device_mac_address
            print(r.json())

    def check_my_devices_location(self):
        auth = HTTPBasicAuth(self.USERNAME, self.PASSWORD)
        r_auth = requests.get(self.AUTH_SERVER_URL + '/users/{}/devices'.format(self.USER_ID), auth=auth)
        devices = [dev['id'] for dev in r_auth.json()['devices']]

        locations = {id: None for id in devices}
        for dev in devices:
            r_loc = requests.get(self.LOCATIONS_SERVER_URL + '/{}'.format(dev))
            locations[dev] = r_loc.json()['location']

        print(locations)
        return locations

    """Devices Interface"""
    def update_my_location(self):
        import random
        location = (random.random() * 120, random.random() * 120)
        data = {
            'location': str(location),
            'mac_address': self.MAC_ADDRESS
        }
        r_loc = requests.post(self.LOCATIONS_SERVER_URL + '/{}'.format(self.DEVICE_ID), json=data)

        if r_loc.status_code == 201:
            print(r_loc.json())

    def generate_private_public_keys(self):
        pass


client = ClientApp()
client.register_user("mustafa_12", "1291241241")

client.add_this_device("ASFAODWF3")
client.update_my_location()

client.check_my_devices_location()

