import os
import json
import logging
from flask import Flask, render_template, request, redirect, url_for
from flask_mqtt import Mqtt
import requests
from base64 import b64decode
import ssl
from threading import Timer

log_file = 'application.log'
logging.basicConfig(filename=log_file, level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

CONFIG_FILE = 'config.json'

default_config = {
    "MQTT_BROKER_URL": "localhost",
    "MQTT_BROKER_USERNAME": "bblp",
    "MQTT_BROKER_PASSWORD": "",
    "BAMBU_REGION": "local",
    "BAMBU_DEVICES": {},
    "BAMBU_DEVICE_ID": 0,
    "BAMBU_API_URL": 'https://api.bambulab.com/v1',
    "BAMBU_EMPTY_TRAY_ID": 0,
    "LOG_LEVEL": "DEBUG"
}

app = Flask(__name__)

def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as file:
            return json.load(file)
    else:
        save_config(default_config)
        return default_config


def save_config(config):
    with open(CONFIG_FILE, 'w') as file:
        json.dump(config, file, indent=4)


config = load_config()

log_level = config.get('LOG_LEVEL', 'DEBUG').upper()
logging.getLogger().setLevel(getattr(logging, log_level))

app.config['MQTT_BROKER_URL'] = config['MQTT_BROKER_URL']
app.config['MQTT_BROKER_PORT'] = 8883
app.config['MQTT_USERNAME'] = config['MQTT_BROKER_USERNAME']
app.config['MQTT_PASSWORD'] = config['MQTT_BROKER_PASSWORD']
app.config['MQTT_KEEPALIVE'] = 60
app.config['MQTT_TLS_ENABLED'] = True
app.config['MQTT_TLS_INSECURE'] = False
app.config['MQTT_TLS_VERSION'] = ssl.PROTOCOL_TLS
app.config['MQTT_TLS_CERT_REQS'] = ssl.CERT_NONE

mqtt = Mqtt(app, connect_async=True)

@app.route('/')
def index():
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        region = request.form['region']
        config['BAMBU_REGION'] = region

        if region == 'local':
            config['MQTT_BROKER_URL'] = request.form['ip']
        else:
            config['MQTT_BROKER_URL'] = 'cn.mqtt.bambulab.com' if region == 'China' else 'us.mqtt.bambulab.com'
            config['BAMBU_API_URL'] = 'https://api.bambulab.cn/v1' if region == 'China' else 'https://api.bambulab.com/v1'
            credentials = {'account': email, 'password': password}
            res = requests.post(f'{config['BAMBU_API_URL']}/user-service/user/login', json=credentials, timeout=10)
            if not res.ok:
                logging.error(f'login failed({res.status_code}): {res.text}')
                return "failed"
            else:
                token = res.json()['accessToken']
                payload = token.split('.')[1]
                payload += '=' * ((4 - len(payload) % 4) % 4)
                config['MQTT_BROKER_USERNAME'] = json.loads(b64decode(payload))['username']
                config['MQTT_BROKER_PASSWORD'] = token

        save_config(config)
        app.config['MQTT_BROKER_URL'] = config['MQTT_BROKER_URL']
        app.config['MQTT_BROKER_USERNAME'] = config['MQTT_BROKER_USERNAME']
        app.config['MQTT_BROKER_PASSWORD'] = config['MQTT_BROKER_PASSWORD']
        return "success"

    return render_template('login.html')


@app.route('/set_filament', methods=['GET', 'POST'])
def set_ams_filament():
    if request.method == 'POST':
        filament_id = request.form['filament_id']
        color = request.form['filament_color']
        tray_id = int(request.form['tray_id'])
        filament_setting = get_slicer_setting(config['BAMBU_FILAMENT_LIST'][filament_id]['setting_id'])

        if tray_id == 0 and config['BAMBU_EMPTY_TRAY_ID'] > 0:
            tray_id = config['BAMBU_EMPTY_TRAY_ID']
        tray_id -= 1

        payload = {
            "print": {
                "command": "ams_filament_setting",
                "ams_id": 0, # hardcoded ams_id = 0
                "tray_id": int(tray_id),
                "tray_info_idx": filament_id,
                "tray_color": color.upper(),
                "nozzle_temp_min": int(filament_setting['setting']['nozzle_temperature_range_low'][0]),
                "nozzle_temp_max": int(filament_setting['setting']['nozzle_temperature_range_high'][0]),
                "tray_type": filament_setting['setting']['filament_type'][0],
            }
        }
        publish_request(payload)
        return payload

    return render_template('set_filament.html', filament_list=config['BAMBU_FILAMENT_LIST'])


@mqtt.on_connect()
def handle_connect(client, userdata, flags, rc):
    if rc == 0:
        logging.info("Connected to MQTT broker successfully")
        bambu_device_id = config['BAMBU_DEVICES'][config['BAMBU_DEVICE_ID']]['dev_id']
        topic = f"device/{bambu_device_id}/report"
        mqtt.subscribe(topic)
        logging.info(f"Subscribed to {topic}")

        update_status()
    else:
        logging.error(f"Failed to connect with result code {rc}.")


@mqtt.on_disconnect()
def handle_disconnect():
    logging.warning(f"Disconnected from MQTT broker.")


@mqtt.on_message()
def handle_mqtt_message(client, userdata, message):
    msg = json.loads(message.payload.decode("utf-8"))
    if "print" in msg:
        data = msg['print']
        if "ams" in data:
            for tray in data['ams']['ams'][0]['tray']: # hardcoded ams_id = 0
                if 'tray_info_idx' not in tray:
                    config['BAMBU_EMPTY_TRAY_ID'] = int(tray['id']) + 1
                    save_config(config)
                    break


def bambu_request(type, uri):
    headers = {'Authorization': 'Bearer ' + config['MQTT_BROKER_PASSWORD']}
    res = requests.get(f'{config['BAMBU_API_URL']}{uri}', headers=headers, timeout=10)
    if not res.ok:
        logging.error(f'Request {uri} failed{res.status_code}): {res.text}')
        return None
    with open(f"debug_{type}.json", 'w') as file:
        json.dump(res.json(), file, indent=4)

    return res.json()

def update_devices():
    config['BAMBU_DEVICES'] = bambu_request('devices', '/iot-service/api/user/bind')['devices']

def update_filament_settings():
    slicer_version = bambu_request('resource', '/iot-service/api/slicer/resource')['software']['version']
    settings = bambu_request('settings', f'/iot-service/api/slicer/setting?version={slicer_version}')
    filament_list = {}
    for filament in settings['filament']['public']:
        filament['private'] = False
        filament_list[filament['filament_id']] = filament
    for filament in settings['filament']['private']:
        filament['private'] = True
        filament_list[filament['filament_id']] = filament

    config['BAMBU_FILAMENT_LIST'] = filament_list

def get_slicer_setting(setting_id):
    return bambu_request('setting', f'/iot-service/api/slicer/setting/{setting_id}')

def publish_request(payload):
    bambu_device_id = config['BAMBU_DEVICES'][config['BAMBU_DEVICE_ID']]['dev_id']
    topic = f"device/{bambu_device_id}/request"
    (res, id) = mqtt.publish(topic, json.dumps(payload))
    return id

def update_status():
    payload = {
        "pushing": {
            "command": "pushall"
        }
    }
    publish_request(payload)
    update_devices()
    update_filament_settings()
    Timer(10, update_status).start()


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)