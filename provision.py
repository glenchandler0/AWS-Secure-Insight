import json

import serial
import serial.tools.list_ports
import requests


REST_WRITE_HEADERS = {'Content-Type': 'application/json', 'Accept': 'application/json'}


def send_csr(csr):
    session = requests.session()

    user_dict = {
        "login_id": BASIC_LOGIN,
        "password": BASIC_PASSWD,
        "api_key": API_KEY
    }
    response = session.post('https://api-dev.mediumone.com/v2/login', data=json.dumps(user_dict),
                            headers=REST_WRITE_HEADERS)

    if response.status_code != 200:
        print("Error logging in", response.content)
        return

    response = session.post("https://api-dev.mediumone.com/v2/certs", data=json.dumps({
        "csr": csr
    }))

    if response.status_code != 200:
        raise Exception("Error getting cert: {}".format(response.content))

    body = response.json()
    return body['crt']


def write_to_atemel(command, data, debug=False):
    """
    data: binary data
    return: binary string converted from hex string response
    """

    with serial.Serial(next(x for x in serial.tools.list_ports.comports() if x.pid == 0x2404 and x.vid == 0x3eb).device, 115200) as ser:
        ser.timeout = 10
        tx = 'aws:{}({})\n'.format(command, ','.join(data))
        if debug:
            print "Sending: {}\n\n{} bytes: {}".format(tx, len(tx), [ord(x) for x in tx])
        ser.write(tx)
        msg = ser.read(10*1024)
        if msg[0:2] != '00':
            raise Exception('Atmel command failed: {}'.format(msg))
    return ''.join(chr(int(x + y, 16)) for x, y in zip(msg[3:-1:2], msg[4:-1:2]))


def get_csr():
    return write_to_atemel('c', [''])


def send_device_cert(cert):
    write_to_atemel('sc', ['03', cert], True)


def send_signer_cert(cert):
    write_to_atemel('sc', ['01', cert])


if __name__ == '__main__':
    import sys

    _, URL, API_KEY, API_BUSINESS_LOGIN, API_BUSINESS_PASSWD, BASIC_LOGIN, BASIC_PASSWD, PROJECT_MQTT_ID, BASIC_MQTT_ID  = sys.argv

    csr = get_csr()
    cert = send_csr(csr)
    send_device_cert(cert)
    open('sent_to_device.pem', 'w').write(cert)
    #send_signer_cert(open('signer.pem', 'r').read())

    verify_cert = write_to_atemel('g', ['03', '00'])
    print verify_cert
    open('received_from_device.pem', 'w').write(verify_cert)

