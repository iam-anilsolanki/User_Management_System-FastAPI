# models.py

from sqlalchemy import Column , Integer , String , ForeignKey , Table , Date , Boolean
from sqlalchemy.orm import declarative_base , relationship
from database import engine
from database import SessionLocal

Base = declarative_base()


class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String(30),nullable=False,unique=True)
    email = Column(String(255),nullable=False,unique=True)
    password = Column(String(255),nullable=False)
    role_id = Column(Integer,ForeignKey('roles.id',ondelete='SET NULL'),index=True,nullable=True)
    role = relationship('Role',back_populates='users')
    is_active = Column(Boolean,default=True)
    profile = relationship('Profile',back_populates='user',cascade="all,delete-orphan",uselist=False)
    email_verified = Column(Boolean, default=False)



class Profile(Base):
    __tablename__ = 'profiles'
    id = Column(Integer,primary_key=True)
    first_name = Column(String(20),nullable=False)
    last_name = Column(String(20),nullable=True)
    bio = Column(String(255))
    avatar_url = Column(String(255))
    dob = Column(Date)
    user_id = Column(Integer,ForeignKey('users.id'),unique=True)
    user = relationship('User',back_populates='profile')


role_permission_table = Table(
    'role_permission',Base.metadata,
    Column('role_id',ForeignKey('roles.id') ,primary_key=True),
    Column('permission_id',ForeignKey('permissions.id'),primary_key=True)
)

class Role(Base):
    __tablename__ = 'roles'
    id = Column(Integer,primary_key=True)
    name = Column(String(255),unique=True,nullable=False)
    users = relationship('User',back_populates='role')
    permissions = relationship('Permission',secondary=role_permission_table ,back_populates='roles')



class Permission(Base):
    __tablename__ = 'permissions'
    id = Column(Integer,primary_key=True)
    name = Column(String(255),unique=True)
    roles = relationship('Role',secondary=role_permission_table,back_populates='permissions')

Base.metadata.create_all(bind=engine)