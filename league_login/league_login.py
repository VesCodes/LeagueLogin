import time
import json
import base64
import zlib

import yaml
import requests
from requests import HTTPError


def get_region_data(region):
    region = region.lower()

    release = "pbe" if region == "pbe1" else "live"
    release_url = "http://l3cdn.riotgames.com/releases/" + release + "/projects/league_client/releases"

    listing_res = requests.get(release_url + "/releaselisting")
    if listing_res.status_code != 200:
        raise HTTPError("league-login: failed to get release listing", response = listing_res)

    client_ver = listing_res.text.split("\n")[0].strip()

    # @TODO(ves): This is troublesome with new patches as it takes a while before a manifest is available;
    # could possibly skip manifest and just bruteforce try every version in order until we hit a system.yaml?
    manifest_res = requests.get(release_url + "/" + client_ver + "/packages/files/packagemanifest")
    if manifest_res.status_code != 200:
        raise HTTPError("league-login: failed to get package manifest", response = manifest_res)

    manifest = manifest_res.text.splitlines()
    yaml_path = next(x for x in manifest if "files/system.yaml.compressed" in x).split(",")[0]

    yaml_res = requests.get("http://l3cdn.riotgames.com/releases/" + release + yaml_path)
    if yaml_res.status_code != 200:
        raise HTTPError("league-login: failed to get system.yaml", response = yaml_res)

    yaml_data = zlib.decompress(yaml_res.content)
    yaml_data = yaml.load(yaml_data)

    region_data = None

    for yaml_region in yaml_data["region_data"].values():
        if yaml_region["rso_platform_id"].lower() == region:
            region_data = {
                "platform_id": yaml_region["rso_platform_id"],
                "rso_assertion": yaml_region["rso"]["token"],
                "lq_url": yaml_region["servers"]["lcds"]["login_queue_url"],
            }

            break

    if region_data is None:
        raise ValueError("Failed to find specified region in system.yaml")

    return region_data


class RSO:
    def __init__(self, region_data):
        openid_config_res = requests.get("https://auth.riotgames.com/.well-known/openid-configuration")
        if openid_config_res.status_code != 200:
            raise HTTPError("league-rso: failed to get openid config", response = openid_config_res)

        self.openid_config = openid_config_res.json()
        self.region_data = region_data

        self._access_token = None
        self.refresh_token = None
        self.issued_at = 0
        self.expires_at = 0

    def authorise(self, username, password):
        auth_res = requests.post(
            self.openid_config["token_endpoint"],
            data = {
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": self.region_data["rso_assertion"],
                "grant_type": "password",
                "username": self.region_data["platform_id"] + "|" + username,
                "password": password,
                "scope": "openid offline_access lol ban profile email phone"
            }
        )

        if auth_res.status_code != 200:
            raise HTTPError("league-rso: failed to authorise", response = auth_res)

        self._process_token(auth_res.json())

    def refresh(self):
        refresh_res = requests.post(
            self.openid_config["token_endpoint"],
            data = {
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": self.region_data["rso_assertion"],
                "grant_type": "refresh_token",
                "refresh_token": self.refresh_token
            }
        )

        if refresh_res.status_code != 200:
            raise HTTPError("league-rso: failed to refresh token", response = refresh_res)

        self._process_token(refresh_res.json())

    @property
    def access_token(self):
        if self._access_token is not None and time.time() >= self.expires_at:
            self.refresh()

        return self._access_token

    def _process_token(self, response):
        self._access_token = response["access_token"]
        self.refresh_token = response["refresh_token"]

        # @NOTE(ves): This is pedantic; alternatively just get the current unix timestamp
        payload = str(self._access_token.split(".")[1])
        payload = base64.urlsafe_b64decode(payload + "=" * (4 - len(payload) % 4))
        payload = json.loads(payload.decode("utf-8"))

        self.issued_at = payload["iat"]
        self.expires_at = payload["exp"]


class Queue:
    def __init__(self, region_data):
        self.region_data = region_data

        self.rso = RSO(region_data)
        self.token = None

    def login(self, username, password):
        if self.rso.access_token is None:
            self.rso.authorise(username, password)

        userinfo_res = requests.post(
            self.rso.openid_config["userinfo_endpoint"],
            headers = { "Authorization": "Bearer " + self.rso.access_token }
        )

        if userinfo_res.status_code != 200:
            raise HTTPError("league-login: failed to get userinfo", response = userinfo_res)

        auth_res = requests.post(
            self.region_data["lq_url"] + "/authenticate/RSO",
            headers = { "authorization": "Bearer " + self.rso.access_token },
            data = { "userinfo": userinfo_res.text }
        )

        if auth_res.status_code != 200:
            raise HTTPError("league-login: failed to authorise", response = auth_res)

        auth = auth_res.json()

        if auth["status"] == "BUSY":
            raise HTTPError("league-login: login queue is busy", response = auth_res)

        if auth["status"] == "QUEUE":
            initial_tickers = {}
            assigned_ticker = None

            for ticker in auth["tickers"]:
                if ticker["champ"] == auth["champ"]:
                    initial_tickers[str(ticker["node"])] = {
                        "id": ticker["id"], "current": ticker["current"]
                    }

                if ticker["node"] == auth["node"]:
                    assigned_ticker = ticker

            assert assigned_ticker is not None
            ticker_node = str(assigned_ticker["node"])
            ticker_target = assigned_ticker["id"]
            ticker_at = assigned_ticker["current"]
            ticker_url = self.region_data["lq_url"] + "/ticker/" + assigned_ticker["champ"]

            while ticker_at < ticker_target:
                ticker_res = requests.get(ticker_url)

                if ticker_res.status_code == 200:
                    tickers = ticker_res.json()
                    ticker_at = int(tickers[ticker_node], 16)

                    queue_pos = 0
                    for node, at in tickers.items():
                        if node in initial_tickers:
                            queue_pos += initial_tickers[node]["id"] - int(at, 16)

                    queue_pos = max(0, queue_pos)
                    if queue_pos == 0:
                        break

                # @TODO(ves): Async? Also check how the client calcs delay
                time.sleep(auth["delay"] / 1000)

            self.rso.refresh()

            token_res = requests.post(self.region_data["lq_url"] + "/token", json = auth["lqt"])
            if token_res.status_code != 200:
                raise HTTPError("league-login: failed to get token", response = token_res)

            self.token = token_res.json()

        if auth["status"] == "LOGIN":
            self.token = auth
