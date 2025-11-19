import random
from datetime import timedelta
from time import timezone, time
from fastapi import FastAPI , Depends
from fastapi.security import OAuth2PasswordBearer , OAuth2PasswordRequestForm
from database import SessionLocal
from schemas import *
from crud import *
from models import User
from auth import verify_token,create_access_token
from fastapi_mail import ConnectionConfig, MessageSchema, MessageType, FastMail
from os import getenv
from dotenv import load_dotenv
from datetime import datetime , timezone, timedelta
import time
import uuid


load_dotenv()

config = ConnectionConfig(
        MAIL_USERNAME=os.getenv("MAIL_USERNAME"),
        MAIL_PASSWORD=os.getenv("MAIL_PASSWORD"),
        MAIL_FROM=os.getenv("MAIL_FROM"),
        MAIL_PORT=587,
        MAIL_SERVER="smtp.gmail.com",
        MAIL_STARTTLS=True,
        MAIL_SSL_TLS=False,
        USE_CREDENTIALS=True
)


reset_token_storage = {}
otp_storage = {}


def generate_otp():
    return "".join([str(random.randint(0,9))for _ in range(6)])


def check_hash_password(password):
    is_proper = validate_password(password)
    if not is_proper:
        raise HTTPException(
            status_code=400,
            detail='Unprocessable data, Password should have atleast 1 Capital Letter , 1 Small Letter , 1 Special Character , 1 Digit and atleast length of 8 character'
        )
    return bcrypt.hashpw(password.encode(),bcrypt.gensalt()).decode()


oauth2_scheme = OAuth2PasswordBearer(tokenUrl='auth/token')

app = FastAPI()



def get_db():
    db = SessionLocal()
    try :
        yield db
    finally:
        db.close()


def get_current_user(token:str = Depends(oauth2_scheme)):
    user_data = verify_token(token)
    if user_data is None:
        raise HTTPException(
            status_code=404,
            detail="Invalid or expired token"
        )
    return user_data


def check_permission(permission_name):
    def get_user(
        current_user: dict = Depends(get_current_user),
        db: Session = Depends(get_db)
    ):
        user = db.query(User).filter(User.username == current_user["username"]).first()
        listp = [j.name for j in user.role.permissions]
        if permission_name not in listp:
            raise HTTPException(
                status_code=400,
                detail='You don\'t have permission to access'
            )
        return user
    return get_user


@app.get('/')
def Welcome_message():
    return {'message':'Welcome to User Management System'}


@app.post('/auth/token')
def login(form_data :OAuth2PasswordRequestForm = Depends(),db:Session=Depends(get_db)):
    user = db.query(User).filter(User.username==form_data.username).first()
    if not user:
        raise HTTPException(status_code=401,detail='username or password is invalid')
    if not bcrypt.checkpw(form_data.password.encode(),user.password.encode()):
        raise HTTPException(status_code=401,detail='username or password is invalid')
    if user.is_active == False:
        raise HTTPException(status_code= 403,detail='Forbidden , account is not active')
    access_token = create_access_token(data = {'sub':user.username,'role_id':user.role_id})
    return {'access_token':access_token,'token_type':'bearer'}


@app.middleware("http")
async def log_middleware(request, call_next):
    start = time.time()
    print(f"Incoming request: {request.method} {request.url}")

    response = await call_next(request)

    duration = time.time() - start
    print(f"Completed in {duration:.4f} seconds")

    return response


@app.post('/forget-password')
async def forget_password(request: OTPRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == request.email).first()
    if not user:
        return {"message": "If account exists, reset link sent"}

    token = str(uuid.uuid4())
    expiration = datetime.now(timezone.utc) + timedelta(minutes=30)

    reset_token_storage[user.email] = {"token": token, "expires_at": expiration}

    reset_link = f"http://localhost:8000/reset-password-page?token={token}&email={user.email}"

    html_content = f"""
        <p>Click below to reset your password:</p>
        <a href="{reset_link}">{reset_link}</a>
        <p>This link is valid for 30 minutes.</p>
    """

    message = MessageSchema(
        subject="Password Reset Link",
        recipients=[user.email],
        body=html_content,
        subtype=MessageType.html
    )

    fm = FastMail(config)
    await fm.send_message(message)

    return {"message": "If account exists, reset link sent"}


@app.post('/reset-password')
def reset_password(request: ResetPasswordRequest, db: Session = Depends(get_db)):
    stored = reset_token_storage.get(request.email)

    if not stored:
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    if stored["token"] != request.token or datetime.now(timezone.utc) > stored["expires_at"]:
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    user = db.query(User).filter(User.email == request.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    hashed = check_hash_password(request.new_password)
    user.password = hashed
    db.commit()

    del reset_token_storage[request.email]

    return {"message": "Password has been changed successfully"}


@app.post('/email-verification')
async def email_verification(request:OTPRequest,db:Session=Depends(get_db),current_user= Depends(check_permission('verify'))):
    if current_user.email != request.email:
        raise HTTPException(status_code=400 , detail='Given email is not associated with your account')
    user = db.query(User).filter(User.email==request.email).first()
    if not user:
        return {'message': 'If account with email exists,OTP has been sent.'}
    if user.email_verified:
        return {'message':'Email is already verified'}
    otp = generate_otp()
    expiration = datetime.now(timezone.utc)+timedelta(minutes=10)
    otp_storage[request.email] = {'otp':otp,'expires_at':expiration}
    html_content = f'''
    <p> You OTP for email verification for username <b><big> {user.username} </big></b> is : </p>
        <h2 style="font-weight: bold; color: #333;">{otp}</h2>
    <p> This otp is valid for 10 minutes
    '''
    message = MessageSchema(
        subject='Your Email verification OTP',
        recipients=[request.email],
        body = html_content,
        subtype=MessageType.html
    )
    fm = FastMail(config)
    await fm.send_message(message)
    return {'message': 'If account with email exists,OTP has been sent.'}


@app.post('/email-verification/otp_check')
def check_otp(request:EmailVerificationOTP,db:Session = Depends(get_db),current_user=Depends(check_permission('verify'))):
    if current_user.email != request.email:
        raise HTTPException(status_code=400 , detail='Given email is not associated with your account')
    stored_otp = otp_storage.get(request.email)
    if not stored_otp:
        raise HTTPException(status_code=400, detail='Invalid request or OTP is expired')
    if stored_otp['otp'] != request.otp or stored_otp['expires_at'] < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail='Invalid request or OTP is expired')
    user = db.query(User).filter(User.email == request.email).first()
    if not user:
        raise HTTPException(status_code=404 , detail='User not Found')
    user.email_verified = True
    db.commit()
    db.refresh(user)
    del otp_storage[request.email]
    return {'message':'Email is verified'}


@app.post('/user',response_model=UserShow)
def add_NewUser(user:UserCreate,db: Session = Depends(get_db)):
    return add_User(user,db)


@app.get('/users',response_model=list[UserShow])
def all_user(User_count:Optional[int]=10 ,User_skip:Optional[int]=0,user_name:Optional[str]=None, db:Session = Depends(get_db),current_user: User = Depends(check_permission('view_users'))):
    if not current_user.email_verified:
        raise HTTPException(status_code=403,detail='First verify your email')
    if User_count<0:
        raise HTTPException(status_code=400,detail="Bad Request")
    if user_name==None:
        a = db.query(User).offset(User_skip).limit(User_count).all()
    else:
        a = db.query(User).filter(func.lower(User.username)==user_name.lower()).first()
        if not a:
            raise HTTPException(status_code=400,detail="Bad Request")
        return [a]
    return a


@app.delete('/delete/{username}')
def delete_user(user:UserDelete,db:Session=Depends(get_db),current_user: User = Depends(check_permission('delete_user'))):
    if not current_user.email_verified:
        raise HTTPException(status_code=403,detail='First verify your email')
    return delete_User(user,db,current_user)


@app.patch('/users/me/profile',response_model=UserProfileShow)
def add_profile(userP:UserProfile,db:Session = Depends(get_db),current_user=Depends(check_permission('update_profile'))):
    if not current_user.email_verified:
        raise HTTPException(status_code=403,detail='First verify your email')
    return add_Profile(userP,current_user.username,db)


@app.patch('/users/me/update_password')
def change_password(user:UserPass, db:Session = Depends(get_db),current_user: User = Depends(check_permission('change_password'))):
    if not current_user.email_verified:
        raise HTTPException(status_code=403,detail='First verify your email')
    return change_Password(user,current_user.username,db)


@app.patch('/users/{username}/status',response_model=UserShow)
def change_status(user:StatusChange,db:Session=Depends(get_db),current_user:User = Depends(check_permission('change_status'))):
    if not current_user.email_verified:
        raise HTTPException(status_code=403,detail='First verify your email')
    return change_Status(user,db)
