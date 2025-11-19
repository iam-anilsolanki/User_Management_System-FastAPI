# auth.py

from jose import JWTError ,jwt
from datetime import datetime,timedelta
from dotenv import load_dotenv
import os

load_dotenv()

SECRET_KEY = os.getenv('SECRET_KEY')
ALGORITHM = 'HS256'
ACCESS_TOKEN_EXPIRE_MINUTES = 15

def create_access_token(data:dict, expires_data : timedelta | None=None):
    to_encode = data.copy()
    expire = datetime.utcnow()+(expires_data or timedelta(minutes=15))
    to_encode.update({'exp':expire})
    return jwt.encode(to_encode,SECRET_KEY,algorithm=ALGORITHM)

def verify_token(token:str):
    try:
        payload = jwt.decode(token,SECRET_KEY,algorithms=[ALGORITHM])
        username = payload.get('sub')
        role_id = payload.get('role_id')

        if username is None:
            return None
        return {'username':username,'role_id':id}

    except JWTError:
        return None


