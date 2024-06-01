"""
  JWT token cotains three parts
    eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9  /header/
    .eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ  /payload/
    .SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c  /secretkey or signature/

    1. header -> contains json object
        {
          'typ': '',
          'alg': 'HS256' 
        }

    2. payaload -> user data
       {
         id: 1,
         username: 'user name etc'
         'email': 'al@gmail.com'
       }
    
    3. signature(secret key) -> used to encryption and decryption

"""

import json
import hmac
from datetime import datetime
import time
from hashlib import sha256
from base64 import urlsafe_b64encode, urlsafe_b64decode

def encode(payload, key, hash):
    segments = []
    # creating Header of jwt
    header_dict = {
        'typ': 'jwt',
        'alg': 'sha256'
    }

    header_json = json.dumps(header_dict)
    header = urlsafe_b64encode(header_json.encode('utf-8'))
    segments.append(header.decode('utf-8').rstrip('='))
    # payload
    json_payload = json.dumps(payload)
    payload = urlsafe_b64encode(json_payload.encode('utf-8'))
    segments.append(payload.decode('utf-8').rstrip('='))

    # Signautre of jwt
    secret_key = key
    msg = '.'.join(segments)
    hmc= hmac.new(key=secret_key, msg=msg.encode('utf-8'), digestmod=hash)
    signature = urlsafe_b64encode(hmc.digest())
    segments.append(signature.decode().rstrip('='))
    jwt = '.'.join(segments)
    return jwt

def decode(token: str, key, hash):
    
    token_arr = token.split('.')
    msg = token_arr[0:2]
    signature = token_arr[2]
    # return [msg,signature]
    new_hmac = hmac.new(key=key, msg='.'.join(msg).encode(), digestmod=hash)
    new_sign = urlsafe_b64encode(new_hmac.digest()).decode().rstrip('=')
    
    if signature == new_sign: 
        payload = urlsafe_b64decode(msg[1].encode())
        return json.loads(payload.decode())
    else: 
        raise Exception('signature not matched')

    
