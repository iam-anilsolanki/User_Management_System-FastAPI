# database.py

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker , declarative_base
from os import getenv
from dotenv import load_dotenv

load_dotenv()
db_string = getenv("DB_CONNECTION")
engine = create_engine(db_string,echo=True)

SessionLocal = sessionmaker(bind=engine,autocommit=False , autoflush=False)

Base = declarative_base()