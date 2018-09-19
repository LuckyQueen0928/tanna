from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import os


engine = create_engine(os.environ.get('DATABASE_URL'))
DBSession = sessionmaker(bind=engine)
session = DBSession()

logprocesslist = []
indexprocesslist = []

indexTraversalTimeout = 3*60
