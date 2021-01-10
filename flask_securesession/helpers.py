# coding: utf-8

import json

from Crypto.Cipher import AES


def encrypt(self, enckey, data):
    cipher = AES.new(enckey, AES.MODE_CFB, iv=enckey[::-1])
    ciphertext = cipher.encrypt(
        json.dumps(data).encode()
    )
    return ciphertext


def decrypt(self, enckey, ciphertext):
    cipher = AES.new(enckey, AES.MODE_CFB, iv=enckey[::-1])
    data = json.loads(cipher.decrypt(ciphertext))
    return data


def total_seconds(td):
    return td.days * 60 * 60 * 24 + td.seconds
