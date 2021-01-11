# coding: utf-8

import json

from Crypto.Cipher import AES


def encrypt(enckey, data):
    if isinstance(enckey, str):
        enckey = enckey.encode()
    
    if isinstance(data, str):
        data = data.encode()
    elif isinstance(data, dict):
        data = json.dumps(data).encode()
    
    cipher = AES.new(enckey, AES.MODE_CFB, iv=enckey[::-1])
    ciphertext = cipher.encrypt(data)
    return ciphertext


def decrypt(enckey, ciphertext):
    if isinstance(ciphertext, str):
        data = ciphertext.encode()
    if isinstance(enckey, str):
        enckey = enckey.encode()
    
    cipher = AES.new(enckey, AES.MODE_CFB, iv=enckey[::-1])
    data = cipher.decrypt(ciphertext)
    
    try:
        data = json.loads(data)
    except json.JSONDecodeError:
        pass
    
    return data


def total_seconds(td):
    return td.days * 60 * 60 * 24 + td.seconds
