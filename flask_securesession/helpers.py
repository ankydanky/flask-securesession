# coding: utf-8

import json

from Crypto.Cipher import AES
from Crypto.Hash import SHA256


def hashEncryptionKey(secret):
    if isinstance(secret, str):
        secret = secret.encode()
    h = SHA256.new(secret)
    return h.hexdigest().encode()


def encrypt(enckey, data):
    enckey = hashEncryptionKey(enckey)
    
    if isinstance(data, str):
        data = data.encode()
    elif isinstance(data, dict):
        data = json.dumps(data).encode()
    
    cipher = AES.new(enckey[:16], AES.MODE_CFB, iv=enckey[20:36])
    ciphertext = cipher.encrypt(data)
    return ciphertext


def decrypt(enckey, ciphertext):
    enckey = hashEncryptionKey(enckey)

    if isinstance(ciphertext, str):
        data = ciphertext.encode()
    
    cipher = AES.new(enckey[:16], AES.MODE_CFB, iv=enckey[20:36])
    data = cipher.decrypt(ciphertext)
    
    try:
        data = json.loads(data)
    except json.JSONDecodeError:
        pass
    
    return data


def total_seconds(td):
    return td.days * 60 * 60 * 24 + td.seconds
