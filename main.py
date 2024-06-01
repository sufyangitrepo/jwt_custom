import jwt
from datetime import datetime
from hashlib import sha256

if __name__ == '__main__':
    now = datetime.now()
    exp = now.replace(hour=now.hour + 1)
    payload = {
        'user': 1,
        'name': 'ali',
        'exp': int(exp.timestamp())
    }
    token = jwt.encode(key=b'abc22441as',hash=sha256, payload=payload)
    payload = jwt.decode(token=token, key=b'abc22441as', hash=sha256)
    print(datetime.fromtimestamp(payload['exp']))
    