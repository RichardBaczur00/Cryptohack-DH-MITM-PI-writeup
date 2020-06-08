from pwn import *
import json
import re


def read_line(CONNECTION):
    raw_data = CONNECTION.recvline()
    raw_data = str(raw_data)
    payload_regex = re.compile('{(.*?)}')
    string_payload = '{' + payload_regex.findall(raw_data)[0] +  '}'
    json_payload = json.loads(string_payload)
    return json_payload


def send_data(CONNECTION, payload):
    json_payload = json.dumps(payload)
    CONNECTION.send(json_payload)
