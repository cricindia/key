import base64
import json
import os
import traceback
import requests
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS

from pywidevine.cdm import Cdm
from pywidevine.device import Device
from pywidevine.pssh import PSSH

app = Flask(__name__, template_folder='../templates')
CORS(app)

WVD_DIR = os.path.dirname(__file__)

def parse_headers(raw_str):
    headers = {}
    if not raw_str:
        return headers
    lines = raw_str.replace('\r\n', '\n').split('\n')
    for line in lines:
        line = line.strip()
        if not line or ":" not in line:
            continue
        k, v = line.split(":", 1)
        # CRITICAL: Strip content-length to let requests calculate it automatically
        if k.strip().lower() == "content-length":
            continue
        headers[k.strip()] = v.strip().strip('"').strip("'")
    return headers

def inject_challenge_payload(data, b64_challenge):
    if isinstance(data, dict):
        for k, v in data.items():
            if isinstance(v, str) and "CAQ==" in v:
                data[k] = b64_challenge
            elif k == "licenseChallenge":
                data[k] = b64_challenge
            else:
                inject_challenge_payload(v, b64_challenge)
    elif isinstance(data, list):
        for idx, item in enumerate(data):
            if isinstance(item, str) and "CAQ==" in item:
                data[idx] = b64_challenge
            else:
                inject_challenge_payload(item, b64_challenge)

def deep_find_license_string(data):
    if isinstance(data, dict):
        for key in ["license", "widevine2License", "widevineLicense", "licenseData", "licenseMessage", "stream", "data"]:
            if key in data:
                value = data[key]
                if isinstance(value, str): return value
                if isinstance(value, dict) and "license" in value: return value["license"]
        for value in data.values():
            result = deep_find_license_string(value)
            if result: return result
    elif isinstance(data, list):
        for item in data:
            result = deep_find_license_string(item)
            if result: return result
    return None

def extract_license_bytes(response):
    try:
        response_json = response.json()
        extracted_license = deep_find_license_string(response_json)
        if extracted_license:
            try: return base64.b64decode(extracted_license)
            except Exception: return extracted_license.encode()
    except Exception: pass
    return response.content

# --- Core Router API Endpoints ---

@app.route("/api", methods=["POST"])
def widevine_api():
    cdm = None
    session_id = None
    try:
        data = request.get_json() or {}
        lic_url = data.get("license")
        pssh_val = data.get("pssh")

        if not lic_url or not pssh_val:
            return jsonify({"status": "error", "message": "Missing active License URL or valid PSSH target structure"}), 400

        device_name = data.get("device", "device.wvd")
        proxy = data.get("proxy")
        device_path = os.path.join(WVD_DIR, device_name)

        if not os.path.exists(device_path):
            return jsonify({"status": "error", "message": f"WVD Keypair profile missing"}), 404

        device = Device.load(device_path)
        cdm = Cdm.from_device(device)
        session_id = cdm.open()
        
        try: pssh = PSSH(base64.b64decode(pssh_val))
        except Exception: pssh = PSSH(pssh_val)

        challenge = cdm.get_license_challenge(session_id, pssh, privacy_mode=False)
        b64_challenge_str = base64.b64encode(challenge).decode()
        headers = parse_headers(data.get("headers", ""))
        
        # FIX: Ensure 'cookie' is capitalized to 'Cookie' for the requests library
        if "cookie" in headers:
            headers["Cookie"] = headers.pop("cookie")

        if "Content-Type" not in headers and "content-type" not in headers:
            headers["Content-Type"] = "application/octet-stream"

        proxies = None
        if proxy and str(proxy).strip():
            proxy_str = str(proxy).strip()
            proxies = {"http": proxy_str, "https": proxy_str}

        # Handling of JSON Request Body structure types
        if data.get("json_body") and str(data.get("json_body")).strip():
            try:
                custom_body = json.loads(data.get("json_body"))
                inject_challenge_payload(custom_body, b64_challenge_str)
                headers["Content-Type"] = "application/json"
                res = requests.post(lic_url, json=custom_body, headers=headers, proxies=proxies, timeout=30)
            except Exception as json_err:
                return jsonify({"status": "error", "message": f"Malformed Request JSON Syntax: {str(json_err)}"}), 400
        elif "primevideo.com" in lic_url.lower():
            payload = {"includeHdcpTestKey": True, "licenseChallenge": b64_challenge_str}
            if data.get("playbackEnvelope"): payload["playbackEnvelope"] = data.get("playbackEnvelope")
            if data.get("sessionToken"): payload["sessionHandoffToken"] = data.get("sessionToken")
            headers["Content-Type"] = "application/json"
            res = requests.post(lic_url, json=payload, headers=headers, proxies=proxies, timeout=30)
        else:
            res = requests.post(lic_url, data=challenge, headers=headers, proxies=proxies, timeout=30)

        if res.status_code != 200:
            return jsonify({"status": "error", "message": f"Server fault signature: {res.status_code}", "server_response_text": res.text[:500]}), 400

        lic_bytes = extract_license_bytes(res)
        cdm.parse_license(session_id, lic_bytes)

        keys = []
        for key in cdm.get_keys(session_id):
            if key.type == "CONTENT":
                kid_val = key.kid
                key_val = key.key
                kid_hex = kid_val.hex() if isinstance(kid_val, bytes) else (kid_val.hex if hasattr(kid_val, 'hex') else str(kid_val))
                key_hex = key_val.hex() if isinstance(key_val, bytes) else (key_val.hex if hasattr(key_val, 'hex') else str(key_val))
                keys.append(f"{kid_hex}:{key_hex}")

        return jsonify({"status": "success", "pssh": pssh_val, "keys": keys})

    except Exception as e:
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500
    finally:
        if cdm and session_id:
            try: cdm.close(session_id)
            except Exception: pass

@app.route("/")
def index():
    return render_template("index.html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)