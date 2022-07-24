"""Main DoorBirdPy module."""
import requests
import json
import sys
from urllib.parse import urlencode
from requests import Session, request
from requests.exceptions import HTTPError

from doorbirdpy.schedule_entry import (
    DoorBirdScheduleEntry,
    DoorBirdScheduleEntryOutput,
    DoorBirdScheduleEntrySchedule,
)


class DoorBird(object):
    """Represent a doorbell unit."""

    """
    Initializes the options for subsequent connections to the unit.
    
    :param ip: The IP address of the unit
    :param username: The username (with sufficient privileges) of the unit
    :param password: The password for the provided username
    """

    def __init__(self, ip, username, password, http_session: Session = None):
        self._ip = ip
        self._credentials = username, password
        self._http = http_session or Session()

    """
    Test the connection to the device.
    
    :return: A tuple containing the ready status (True/False) and the HTTP 
    status code returned by the device or 0 for no status
    """

    def ready(self):
        url = self.__url("/bha-api/info.cgi", auth=True)
        try:
            response = self._http.get(url)
            data = response.json()
            code = data["BHA"]["RETURNCODE"]
            return int(code) == 1, int(response.status_code)
        except ValueError:
            return False, int(response.status_code)

    """
    A multipart JPEG live video stream with the default resolution and
    compression as defined in the system configuration.
    
    :return: The URL of the stream
    """

    @property
    def live_video_url(self):
        return self.__url("/bha-api/video.cgi")

    """
    A JPEG file with the default resolution and compression as 
    defined in the system configuration.
    
    :return: The URL of the image
    """

    @property
    def live_image_url(self):
        return self.__url("/bha-api/image.cgi")

    """
    Energize a door opener/alarm output/etc relay of the device.
    
    :return: True if OK, False if not
    """

    def energize_relay(self, relay=1):
        data = self._get_json(
            self.__url("/bha-api/open-door.cgi", {"r": relay}, auth=True)
        )
        return int(data["BHA"]["RETURNCODE"]) == 1

    """
    Turn on the IR lights.
    
    :return: JSON
    """

    def turn_light_on(self):
        data = self._get_json(self.__url("/bha-api/light-on.cgi", auth=True))
        code = data["BHA"]["RETURNCODE"]
        return int(code) == 1

    """
    A past image stored in the cloud.

    :param index: Index of the history images, where 1 is the latest 
    history image
    :return: The URL of the image.
    """

    def history_image_url(self, index, event):
        return self.__url("/bha-api/history.cgi", {"index": index, "event": event})

    """
    Get schedule settings.
    
    :return: A list of DoorBirdScheduleEntry objects
    """

    def schedule(self):
        data = self._get_json(self.__url("/bha-api/schedule.cgi", auth=True))
        return DoorBirdScheduleEntry.parse_all(data)

    """
    Find the schedule entry that matches the provided sensor and parameter
    or create a new one that does if none exists.
    
    :return: A DoorBirdScheduleEntry
    """

    def get_schedule_entry(self, sensor, param=""):
        entries = self.schedule()

        for entry in entries:
            if entry.input == sensor and entry.param == param:
                return entry

        return DoorBirdScheduleEntry(sensor, param)

    """
    Add or replace a schedule entry.
    
    :param entry: A DoorBirdScheduleEntry object to replace on the device
    :return: A tuple containing the success status (True/False) and the HTTP response code
    """

    def change_schedule(self, entry):
        url = self.__url("/bha-api/schedule.cgi", auth=True)
        response = self._http.post(
            url,
            body=json.dumps(entry.export),
            headers={"Content-Type": "application/json"},
        )
        return int(response.status_code) == 200, response.status_code

    """
    Delete a schedule entry.
    
    :param event: Event type (doorbell, motion, rfid, input)
    :param param: param value of schedule entry to delete
    :return: True if OK, False if not
    """

    def delete_schedule(self, event, param=""):
        url = self.__url(
            "/bha-api/schedule.cgi",
            {"action": "remove", "input": event, "param": param},
            auth=True,
        )
        response = self._http.get(url)
        return int(response.status_code) == 200

    """
    The current state of the doorbell.
    
    :return: True for pressed, False for idle
    """

    def doorbell_state(self):
        url = self.__url("/bha-api/monitor.cgi", {"check": "doorbell"}, auth=True)
        response = self._http.get(url)
        response.raise_for_status()

        try:
            return int(response.text.split("=")[1]) == 1
        except IndexError:
            return False

    """
    The current state of the motion sensor.
    
    :return: True for motion, False for idle
    """

    def motion_sensor_state(self):
        url = self.__url("/bha-api/monitor.cgi", {"check": "motionsensor"}, auth=True)
        response = self._http.get(url)
        response.raise_for_status()

        try:
            return int(response.text.split("=")[1]) == 1
        except IndexError:
            return False

    """
    Get information about the device.
    
    :return: A dictionary of the device information:
    - FIRMWARE
    - BUILD_NUMBER
    - WIFI_MAC_ADDR (if the device is connected via WiFi)
    - RELAYS list (if firmware version >= 000108) 
    - DEVICE-TYPE (if firmware version >= 000108)
    """

    def info(self):
        url = self.__url("/bha-api/info.cgi", auth=True)
        data = self._get_json(url)
        return data["BHA"]["VERSION"][0]

    """
    Get all saved favorites.
    
    :return: dict, as defined by the API.
    Top level items will be the favorite types (http, sip),
    which each reference another dict that maps ID
    to a dict with title and value keys.
    """

    def favorites(self):
        return self._get_json(self.__url("/bha-api/favorites.cgi", auth=True))

    """
    Add a new saved favorite or change an existing one.
    
    :param fav_type: sip or http
    :param title: Short description
    :param value: URL including protocol and credentials
    :param fav_id: The ID of the favorite, only used when editing existing favorites
    :return: successful, True or False
    """

    def change_favorite(self, fav_type, title, value, fav_id=None):
        args = {"action": "save", "type": fav_type, "title": title, "value": value}

        if fav_id:
            args["id"] = int(fav_id)

        response = self._http.get(self.__url("/bha-api/favorites.cgi", args, auth=True))
        return int(response.status_code) == 200

    """
    Delete a saved favorite.

    :param fav_type: sip or http
    :param fav_id: The ID of the favorite
    :return: successful, True or False
    """

    def delete_favorite(self, fav_type, fav_id):
        url = self.__url(
            "/bha-api/favorites.cgi",
            {"action": "remove", "type": fav_type, "id": fav_id},
            auth=True,
        )

        response = self._http.get(url)
        return int(response.status_code) == 200

    """
    Live video request over RTSP.
    
    :param http: Set to True to use RTSP over HTTP
    :return: The URL for the MPEG H.264 live video stream
    """

    @property
    def rtsp_live_video_url(self, http=False):
        return self.__url(
            "/mpeg/media.amp", port=(8557 if http else 554), protocol="rtsp"
        )

    """
    The HTML5 viewer for interaction from other platforms.
    
    :return: The URL of the viewer
    """

    @property
    def html5_viewer_url(self):
        return self.__url("/bha-api/view.html")

    """
    Create a URL for accessing the device.

    :param path: The endpoint to call
    :param args: A dictionary of query parameters
    :param port: The port to use (defaults to 80)
    :param auth: Set to False to remove the URL authentication
    :param protocol: Allow protocol override
    :return: The full URL
    """

    def __url(self, path, args=None, port=80, auth=True, protocol="http"):
        query = urlencode(args) if args else ""

        if auth:
            template = "{}://{}@{}:{}{}"
            user = ":".join(self._credentials)
            url = template.format(protocol, user, self._ip, port, path)
        else:
            template = "{}://{}:{}{}"
            url = template.format(protocol, self._ip, port, path)

        if query:
            url = "{}?{}".format(url, query)

        return url

    """
    Get URL on the device.
    
    :param url: The full URL to the API call
    :return: The JSON-decoded data sent by the device
    """

    def _get_json(self, url):
        response = self._http.get(url)
        response.raise_for_status()
        return response.json()
