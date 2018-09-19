#coding:utf-8
#!/usr/bin/python

import os
import io
import traceback
import time
import os.path
import shutil
from xml.etree.ElementTree import Element, SubElement,  ElementTree
import xml.etree.ElementTree as ETS
ETS.register_namespace('', "http://peachfuzzer.com/2012/Peach")
from sqlalchemy import desc
from sqlalchemy import *
from sqlalchemy.orm import sessionmaker,mapper
from sqlalchemy.ext.declarative import declarative_base
import ConfigParser


Base = declarative_base()


class peach_pit(Base):
    __tablename__ = 'peach_pit'

    peach_id = Column(Integer, primary_key=True)
    pit_name = Column(String)
    pit_hash = Column(String)
    aid = Column(Integer)
    peach_test = Column(String)


class pit_test_t(Base):
    __tablename__ = 'pit_test_t'

    id = Column(Integer, primary_key=True)
    test = Column(String)
    test_status = Column(Integer)
    peach_id = Column(Integer)


class pit_state_model_t(Base):
    __tablename__ = 'pit_state_model_t'

    id = Column(Integer, primary_key=True)
    state_model = Column(String)
    state_model_status = Column(Integer)
    test_id = Column(Integer,  ForeignKey('pit_test_t.id'))


class pit_state_t(Base):
    __tablename__ = 'pit_state_t'

    id = Column(Integer, primary_key=True)
    state_name = Column(String)
    state_status = Column(Integer)
    state_model_id = Column(Integer, ForeignKey('pit_state_model_t.id'))
    action_count = Column(Integer)
    action_index = Column(Integer)


#全局变量设置pit文件类型
Const_Pit_Format=["xml"]

current_test_id = 0
current_state_model_id = 0
current_state_id = 0

class HandlePeachPit:
    '''这是一个处理peachpit文件的类,由宋哥编写'''
    #类变量，设置文件列表
    fileList = [""]
    #类变量，设置文件计算
    counter = 0

    def __init__(self):
        pass

    #配置文件
    iniDBFile = "url.ini"

    #加载数据库配置信息
    def initDBParam(self):
        global db_url
        db_url = os.environ.get('DATABASE_URL')


    #连接数据库
    def connectDB(self):
        engine = create_engine(db_url)
        db_session = sessionmaker(bind=engine)
        global session
        session = db_session()


    def RecusWalkDir(self, dir, filtrate=0):
        # 本方法递归遍历目的文件夹中所有文件，获取指定格式的文件绝对地址,利用类变量fileList存储地址
        global Const_Pit_Format
        for s in os.listdir(dir):
            newDir = dir+"/"+s
            if os.path.isdir(newDir):
                    self.RecusWalkDir(newDir, 1)
            else:
                if os.path.isfile(newDir):
                    if filtrate:
                        if newDir and (self.GetFileFormat(newDir) in Const_Pit_Format):
                            self.HandlePitFile(newDir)
                    #else:



    def GetFileFormat(self, fileName):
        """返回文件格式"""
        if fileName:
            BaseName=os.path.basename(fileName)
            str=BaseName.split(".")
            return str[-1]
        else:
            return fileName


    def HandlePitFile(self, fileName):
        """处理peach pit文件"""
        tree = ETS.parse(fileName)
        etree = tree.getroot()
        for state_model_node in etree:
            if state_model_node.tag == "{http://peachfuzzer.com/2012/Peach}StateModel":
                state_model_name = state_model_node.attrib['name']
                self.HandleStateModel(state_model_name)
                for state_node in state_model_node:
                    if state_node.tag =="{http://peachfuzzer.com/2012/Peach}State":
                        state_name = state_node.attrib['name']
                        action_index = 0
                        for action_node in state_node:
                            if action_node.tag =="{http://peachfuzzer.com/2012/Peach}Action" and action_node.attrib['type'] == "output":
                                action_index = action_index + 1
                        self.HandleState(state_name, action_index)



    #pit_state_model_t
    def HandleStateModel(self, state_model_name):
        global current_test_id
        global current_state_model_id
        global current_state_id

        if(state_model_name):
            session.commit()
            pit_state_model_m = pit_state_model_t()
            pit_state_model_m.state_model = state_model_name
            pit_state_model_m.state_model_status = 0
            pit_state_model_m.test_id = current_test_id
            session.add(pit_state_model_m)
            session.commit()
            query = session.query(pit_state_model_t.id).order_by(pit_state_model_t.id.desc()).first()
            rs = []
            t = ()
            for t in query:
                rs.append(t)
            current_state_model_id = rs[0]


    def HandleState(self, state_name, action_count):
        global current_test_id
        global current_state_model_id
        global current_state_id
        if(state_name):
            session.commit()
            pit_state_m = pit_state_t()
            pit_state_m.state_name = state_name
            pit_state_m.state_status = 0
            pit_state_m.state_model_id = current_state_model_id
            pit_state_m.action_count = action_count
            pit_state_m.action_index = 1
            session.add(pit_state_m)
            session.commit()
            query = session.query(pit_state_t.id).order_by(pit_state_t.id.desc()).first()
            rs = []
            t = ()
            for t in query:
                rs.append(t)
            current_state_id = rs[0]


    def HandleTest(self, test_name, peach_id):
        global current_test_id
        global current_state_model_id
        global current_state_id

        if(test_name):
            session.commit()
            pit_test_m = pit_test_t()
            pit_test_m.test = test_name
            pit_test_m.test_status = 0
            pit_test_m.peach_id = peach_id
            session.add(pit_test_m)
            session.commit()
            session.commit()
            query = session.query(pit_test_t.id).order_by(pit_test_t.id.desc()).first()
            rs = []
            t = ()
            for t in query:
                rs.append(t)
            current_test_id = rs[0]


if __name__=="__main__":
    b = HandlePeachPit()
    b.initDBParam()
    b.connectDB()
    peach_id = 0
    b.HandleTest("Default", peach_id)
    b.RecusWalkDir(dir="E:/ftp_fuzzing", filtrate=1)
