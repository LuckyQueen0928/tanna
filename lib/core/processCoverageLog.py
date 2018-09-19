from sqlalchemy.ext.declarative import declarative_base
from lib.core.data import session
from sqlalchemy import Column, Integer, String, DateTime, or_
import time
from datetime import datetime

Base = declarative_base()


class Partialnode(Base):
    __tablename__ = 'partial_node_t'
    nid = Column(Integer, primary_key=True)
    id  = Column(Integer)
    tail = Column(Integer)
    parentnode = Column(Integer)
    status = Column(Integer)
    aid = Column(Integer)

    def __repr__(self):
        return '<id %r>' % self.id


class Coverage_log_t(Base):
    __tablename__ = 'coverage_log_t'
    id = Column(Integer, primary_key=True)
    log_time = Column(DateTime, default=datetime.utcnow)
    coverage = Column(String)
    aid = Column(Integer)

    def __repr__(self):
        return '<id %r>' % self.id
        

def getCurrentCoverNum(appid=0):
    coverBblNum = session.query(Partialnode).filter_by(aid=appid)\
        .filter(or_(Partialnode.status == 1, Partialnode.status == 2))\
        .count()
    return coverBblNum


def saveCoverLog(appid=0, timeout=30):
    while True:
        time.sleep(timeout)
        coveredNum = getCurrentCoverNum(appid)
        print('coveredNum:'+str(coveredNum))
        clt = Coverage_log_t(coverage=coveredNum, aid=appid)
        session.add(clt)
        session.commit()

