# schemas.py

from pydantic import BaseModel, field_validator, ConfigDict, EmailStr
from typing import Optional
from datetime import date
from models import Role,User


class UserCreate(BaseModel):
    username : str
    email :str
    password : str
    role_id : Optional[int] = 2

    model_config = ConfigDict(from_attributes=True)


class UserProfile(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    bio: Optional[str] = None
    avatar_url: Optional[str] = None
    dob: Optional[date] = None

    model_config = ConfigDict(from_attributes=True)

class UserProfileShow(BaseModel):
    id:int
    first_name:str
    last_name:str
    bio:str
    avatar_url:str
    dob:date
    user_id : int

    model_config = ConfigDict(from_attributes=True)



class UserShow(BaseModel):
    id : int
    username : str
    email : str
    profile : Optional[UserProfile] = None

    role: Optional[str] = None
    @field_validator('role', mode='before')
    @classmethod
    def get_role_name(cls, role_obj: Role) -> Optional[str]:
        if role_obj:
            return role_obj.name
        return None
    is_active : bool
    email_verified : bool

    model_config = ConfigDict(from_attributes=True)



class updateIs_active(BaseModel):
    username : Optional[str] = None
    email : Optional[str] = None
    new_status : bool

    model_config = ConfigDict(from_attributes=True)

class UserDelete(BaseModel):
    username : str

class UserPass(BaseModel):
    password : str
    new_password : str

class StatusChange(BaseModel):
    username : str
    to_active : bool

class OTPRequest(BaseModel):
    email:str

class ResetPasswordRequest(BaseModel):
    email:str
    otp : str
    new_password : str

class EmailVerificationOTP(BaseModel):
    email:str
    otp : str

class OTPRequest(BaseModel):
    email: EmailStr

class ResetPasswordRequest(BaseModel):
    email: EmailStr
    token: str
    new_password: str






