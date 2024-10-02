import os
import json
import logging
from flask import Flask, render_template, request, redirect, url_for, send_file
from flask_mqtt import Mqtt
from flask_serial import Serial
import requests
from base64 import b64decode
import ssl
from threading import Timer
import io
import qrcode
from serial.tools import list_ports

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
    "BAMBU_ACCESS_TOKEN": "",
    "BAMBU_REFRESH_TOKEN": "",
    "BAMBU_EMPTY_TRAY_ID": 0,
    'SERIAL_BAUDRATE': 9600,
    'SERIAL_TIMEOUT': 10,
    'SERIAL_PORT': "disabled",
    "LOG_LEVEL": "INFO"
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

if config['SERIAL_PORT'] != 'disabled':
    app.config['SERIAL_PORT'] = config['SERIAL_PORT']
    app.config['SERIAL_BAUDRATE'] = int(config['SERIAL_BAUDRATE'])
    app.config['SERIAL_TIMEOUT'] = int(config['SERIAL_TIMEOUT'])
    app.config['SERIAL_BYTESIZE'] = 8
    app.config['SERIAL_PARITY'] = 'N'
    app.config['SERIAL_STOPBITS'] = 1

    ser = Serial(app)
    @ser.on_message()
    def handle_message(message):
        try:
            json_string = message.decode('utf-8').strip()
            data = json.loads(json_string)
            logging.debug(f'SERIAL: received message: {data}')
        except json.JSONDecodeError:
            logging.warning(f'SERIAL: received invalid JSON: {message}')
        set_ams_filament(data['id'], data['color'], 0)

mqtt = Mqtt(app, connect_async=True)
mqtt_connected = False


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
            config['MQTT_BROKER_USERNAME'] = "bblp"
            config['MQTT_BROKER_PASSWORD'] = request.form['accesscode']
        else:
            config['MQTT_BROKER_URL'] = 'cn.mqtt.bambulab.com' if region == 'Chinese Mainland' else 'us.mqtt.bambulab.com'
            config['BAMBU_API_URL'] = 'https://api.bambulab.cn/v1' if region == 'Chinese Mainland' else 'https://api.bambulab.com/v1'
            credentials = {'account': email, 'password': password}
            res = requests.post(f'{config['BAMBU_API_URL']}/user-service/user/login', json=credentials, timeout=10)
            if not res.ok:
                logging.error(f'login failed({res.status_code}): {res.text}')
                return "failed"
            else:
                config['BAMBU_ACCESS_TOKEN'] = res.json()['accessToken']
                config['BAMBU_REFRESH_TOKEN'] = res.json()['refreshToken']
                payload = config['BAMBU_ACCESS_TOKEN'].split('.')[1]
                payload += '=' * ((4 - len(payload) % 4) % 4)
                config['MQTT_BROKER_USERNAME'] = json.loads(b64decode(payload))['username']
                config['MQTT_BROKER_PASSWORD'] = config['BAMBU_ACCESS_TOKEN']

        app.config['MQTT_BROKER_URL'] = config['MQTT_BROKER_URL']
        app.config['MQTT_BROKER_USERNAME'] = config['MQTT_BROKER_USERNAME']
        app.config['MQTT_BROKER_PASSWORD'] = config['MQTT_BROKER_PASSWORD']
        update_devices()
        update_filament_settings()
        save_config(config)

        return redirect(url_for('set_filament'))

    return render_template('login.html')


@app.route('/set_filament', methods=['GET', 'POST'])
def set_filament():
    global mqtt_connected
    if not mqtt_connected and 'BAMBU_FILAMENT_LIST' not in config:
        return redirect(url_for('login'))

    if request.method == 'POST':
        filament_id = request.form['filament_id']
        color = request.form['filament_color']
        tray_id = int(request.form['tray_id'])

        payload = set_ams_filament(filament_id, color, tray_id)
        return payload

    return render_template('set_filament.html', filament_list=config['BAMBU_FILAMENT_LIST'])


@app.route('/api/qr-code', methods=['GET'])
def generate_qr():
    filament_id = request.args.get('filament_id')
    filament_color = request.args.get('filament_color')
    data = {'id': filament_id, 'color': filament_color}
    return send_file(dict_to_qr_code(data), mimetype='image/png')


@app.route('/serial', methods=['GET', 'POST'])
def serial_config():
    msg = ""
    if request.method == 'POST':
        config['SERIAL_PORT'] = request.form['serial_port']
        config['SERIAL_BAUDRATE'] = request.form['baudrate']
        config['SERIAL_TIMEOUT'] = request.form['timeout']

        save_config(config)

        msg = "configuration stored..."

    ports = list_ports.comports()
    serial_devices = [('disabled', 'n/a', '')]
    for port in ports:
        if config['SERIAL_PORT'] == port.device:
            selected = " selected"
        else:
            selected = ""
        serial_devices.append((port.device, port.description, selected))
    return render_template('serial.html', serial_devices=serial_devices,
                           baudrate=config['SERIAL_BAUDRATE'], timeout=config['SERIAL_TIMEOUT'], msg=msg)


@mqtt.on_connect()
def handle_connect(client, userdata, flags, rc):
    global mqtt_connected
    if rc == 0:
        logging.info("Connected to MQTT broker successfully")
        bambu_device_id = config['BAMBU_DEVICES'][config['BAMBU_DEVICE_ID']]['dev_id']
        topic = f"device/{bambu_device_id}/report"
        mqtt.subscribe(topic)
        logging.info(f"Subscribed to {topic}")

        update_status()
        mqtt_connected = True
    else:
        logging.error(f"Failed to connect with result code {rc}.")
        mqtt_connected = False


@mqtt.on_disconnect()
def handle_disconnect():
    logging.warning(f"Disconnected from MQTT broker.")
    mqtt_connected = False


@mqtt.on_message()
def handle_mqtt_message(client, userdata, message):
    msg = json.loads(message.payload.decode("utf-8"))
    found_empty_tray = False
    if "print" in msg:
        data = msg['print']
        if "ams" in data and "ams" in data['ams']:
            for tray in data['ams']['ams'][0]['tray']:  # hardcoded ams_id = 0
                if 'tray_info_idx' not in tray:
                    config['BAMBU_EMPTY_TRAY_ID'] = int(tray['id']) + 1
                    found_empty_tray = True
                    break
            if not found_empty_tray:
                config['BAMBU_EMPTY_TRAY_ID'] = 0
            save_config(config)


def set_ams_filament(filament_id, color, tray_id):
    filament_setting = get_slicer_setting(config['BAMBU_FILAMENT_LIST'][filament_id]['setting_id'])

    if tray_id == 0 and config['BAMBU_EMPTY_TRAY_ID'] > 0:
        tray_id = config['BAMBU_EMPTY_TRAY_ID']
    tray_id -= 1

    if config['BAMBU_FILAMENT_LIST'][filament_id]['private']:
        nozzle_temp_min = config['BAMBU_FILAMENT_LIST'][filament_id]['nozzle_temperature'][0]
        nozzle_temp_max = config['BAMBU_FILAMENT_LIST'][filament_id]['nozzle_temperature'][1]
        filament_type = config['BAMBU_FILAMENT_LIST'][filament_id]['filament_type']
    else:
        nozzle_temp_min = int(filament_setting['setting']['nozzle_temperature_range_low'][0])
        nozzle_temp_max = int(filament_setting['setting']['nozzle_temperature_range_high'][0])
        filament_type = filament_setting['setting']['filament_type'][0]
    payload = {
        "print": {
            "sequence_id": 0,
            "command": "ams_filament_setting",
            "ams_id": 0,  # hardcoded ams_id = 0
            "tray_id": int(tray_id),
            "tray_info_idx": filament_id,
            "tray_color": color.upper(),
            "nozzle_temp_min": nozzle_temp_min,
            "nozzle_temp_max": nozzle_temp_max,
            "tray_type": filament_type,
        }
    }
    publish_request(payload)
    return payload

def bambu_request(type, uri):
    headers = {'Authorization': 'Bearer ' + config['MQTT_BROKER_PASSWORD']}
    res = requests.get(f'{config['BAMBU_API_URL']}{uri}', headers=headers, timeout=10)
    if not res.ok:
        logging.error(f'Request {uri} failed{res.status_code}): {res.text}')
        return None
    #with open(f"debug_{type}.json", 'w') as file:
    #    json.dump(res.json(), file, indent=4)

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

def dict_to_qr_code(data):
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=1,
    )
    qr.add_data(json.dumps(data))
    qr.make(fit=True)

    img = qr.make_image(fill='black', back_color='white')

    img_io = io.BytesIO()
    img.save(img_io, 'PNG')
    img_io.seek(0)

    return img_io

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
