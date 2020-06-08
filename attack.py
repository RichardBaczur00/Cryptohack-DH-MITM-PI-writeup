from pwn import *
import json
import re
from Crypto.Cipher import AES
import hashlib

from Crypto.Util.py3compat import *


def pad(data_to_pad, block_size, style='pkcs7'):
    padding_len = block_size-len(data_to_pad)%block_size
    if style == 'pkcs7':
        padding = bchr(padding_len)*padding_len
    elif style == 'x923':
        padding = bchr(0)*(padding_len-1) + bchr(padding_len)
    elif style == 'iso7816':
        padding = bchr(128) + bchr(0)*(padding_len-1)
    else:
        raise ValueError("Unknown padding style")
    return data_to_pad + padding

def unpad(padded_data, block_size, style='pkcs7'):
    pdata_len = len(padded_data)
    if pdata_len % block_size:
        raise ValueError("Input data is not padded")
    if style in ('pkcs7', 'x923'):
        padding_len = bord(padded_data[-1])
        if padding_len<1 or padding_len>min(block_size, pdata_len):
            raise ValueError("Padding is incorrect.")
        if style == 'pkcs7':
            if padded_data[-padding_len:]!=bchr(padding_len)*padding_len:
                raise ValueError("PKCS#7 padding is incorrect.")
        else:
            if padded_data[-padding_len:-1]!=bchr(0)*(padding_len-1):
                raise ValueError("ANSI X.923 padding is incorrect.")
    elif style == 'iso7816':
        padding_len = pdata_len - padded_data.rfind(bchr(128))
        if padding_len<1 or padding_len>min(block_size, pdata_len):
            raise ValueError("Padding is incorrect.")
        if padding_len>1 and padded_data[1-padding_len:]!=bchr(0)*(padding_len-1):
            raise ValueError("ISO 7816-4 padding is incorrect.")
    else:
        raise ValueError("Unknown padding style")
    return padded_data[:-padding_len]


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

#connection socket
connection = remote('socket.cryptohack.org', 13371)

#DH params
p = 0
g = 0
A = 0
B = 0
my_secret = 3
shared_secret = 0


def process_connection_start(payload):
    p = int(payload['p'], 16)
    g = int(payload['g'], 16)
    A = int(payload['A'], 16)
    B = pow(g, my_secret, p)
    #calculate my own shared secret
    shared_secret = pow(A, my_secret, p)
    send_data(connection, payload)


def break_in():
    infected_payload = {}
    infected_payload['B'] = hex(B)
    #infect the connection between bob and alice with a my secret and block the road between them
    send_data(connection, infected_payload)


def is_pkcs7_padded(message):
    padding = message[-message[-1]:]
    return all(padding[i] == len(padding) for i in range(0, len(padding)))


def decrypt_flag(shared_secret: int, iv: str, ciphertext: str):
    sha1 = hashlib.sha1()
    sha1.update(str(shared_secret).encode('ascii'))
    key = sha1.digest()[:16]
    ciphertext = bytes.fromhex(ciphertext)
    iv = bytes.fromhex(iv)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)

    if is_pkcs7_padded(plaintext):
        return unpad(plaintext, 16).decode('ascii')
    else:
        return plaintext.decode('ascii')


def decrypt_message(message):
    iv = message['iv']
    encrypted_message = message['encrypted_flag']

    print(decrypt_flag(shared_secret, iv, encrypted_message))



def main():
    alice_start = read_line(connection)
    process_connection_start(alice_start)
    #completely ignore bobs key exchange and instead completely take over the conversation
    read_line(connection)
    break_in()
    alice_message = read_line(connection)
    decrypt_message(alice_message)


if __name__ == "__main__":
    main()
