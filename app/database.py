# Database initializtion
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# For mapping
from sqlalchemy.ext.declarative import declarative_base


import json
with open('config.json') as f:
    config = json.load(f)

HOSTNAME = config['hostname']
USER = config['user']
PASSWORD = config['password']
DB_NAME = 'urldata'

url = f'mysql+mysqlconnector://{USER}:{PASSWORD}@{HOSTNAME}:3306/{DB_NAME}'

engine = create_engine(url)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


Base = declarative_base()
