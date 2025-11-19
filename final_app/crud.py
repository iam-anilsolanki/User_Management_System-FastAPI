# crud.py
from sqlalchemy import func
from sqlalchemy.orm import Session
from fastapi import HTTPException
from models import *
from schemas import *
import re
import bcrypt
import os
from dotenv import load_dotenv
from fastapi_mail import ConnectionConfig

load_dotenv()



def validate_email(email):
    pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    matchFound = re.match(pattern,email)
    if matchFound:
        return True
    else:
        return False


def validate_password(password):
    pattern = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$"
    matchFound = re.match(pattern,password)
    if matchFound:
        return True
    else:
        return False


def hash_password(password):
    hashed_password = bcrypt.hashpw(password.encode(),bcrypt.gensalt())
    return hashed_password.decode()



def add_User(user:UserCreate, db:Session):
    checkEmail = validate_email(user.email)
    if checkEmail == False:
        raise HTTPException(
            status_code=422,
            detail='Unprocessable data, Email should be in format of sample@gmail.com'
        )
    checkPassword = validate_password(user.password)
    if checkPassword == False:
        raise HTTPException(
            status_code=422,
            detail='Unprocessable data, Password should have atleast 1 Capital Letter , 1 Small Letter , 1 Special Character , 1 Digit and atleast length of 8 character'
        )
    if_username = db.query(User).filter(User.username==user.username).first()
    if if_username:
        raise HTTPException(
            status_code=409,
            detail='Username already exists'
        )
    if_email = db.query(User).filter(User.email==user.email).first()
    if if_email:
        raise HTTPException(
            status_code=409,
            detail='Email already exists'
        )

    user.password = hash_password(user.password)
    new_user = User(**user.dict())
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user


def delete_User(user:UserDelete,db:Session,current_user):
    if user.username == current_user['username']:
        raise HTTPException(
            status_code=400,
            detail='Bad Request'
        )
    a = db.query(User).filter(func.lower(User.username) == user.username.lower()).first()
    if a:
        db.delete(a)
        db.commit()
        return {'status code':200,'message':'User is deleted successfully'}
    else:
        raise HTTPException(
            status_code=400,
            detail='Username does not exist'
        )


def add_Profile(userP: UserProfile, username1: str, db: Session):
    user = db.query(User).filter(User.username == username1).first()
    if not user:
        raise HTTPException(
            status_code=404,
            detail='User not found'
        )

    existing_profile = db.query(Profile).filter(Profile.user_id == user.id).first()

    if existing_profile:
        update_data = userP.model_dump(exclude_unset=True)
        for key, value in update_data.items():
            setattr(existing_profile, key, value)
        profile_to_return = existing_profile
    else:
        new_profile = Profile(**userP.model_dump(), user_id=user.id)
        db.add(new_profile)
        profile_to_return = new_profile

    db.commit()
    db.refresh(profile_to_return)

    return profile_to_return


def change_Password(user:UserPass,username,db:Session):
    userData = db.query(User).filter(User.username == username).first()
    checkPassword = bcrypt.checkpw(user.password.encode(),userData.password.encode())
    if not userData:
        raise HTTPException(status_code=404, detail="User not found")
    if checkPassword:
        if not validate_password(user.new_password):
            raise HTTPException(
                status_code=403,
                detail='Unprocessable data, Password should have atleast 1 Capital Letter , 1 Small Letter , 1 Special Character , 1 Digit and atleast length of 8 character'
            )
        new_password = hash_password(user.new_password)
        userData.password = new_password
        db.commit()
        db.refresh(userData)
        return {'message':'password is changed'}
    else:
        raise HTTPException(
            status_code=400,
            detail='Password does not match'
        )


def change_Status(user:StatusChange,db:Session):
    if_exist = db.query(User).filter(User.username==user.username).first()
    if not if_exist:
        raise HTTPException(
            status_code=403,
            detail='Bad Request : username does not exists'
        )
    if if_exist.is_active == user.to_active:
        return if_exist
    else:
        if_exist.is_active = user.to_active
        db.commit()
        db.refresh(if_exist)
        return if_exist







