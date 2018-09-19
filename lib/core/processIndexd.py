# -*- coding: utf-8 -*-
# 实现状态遍历调控的AGENT

from sqlalchemy.ext.declarative import declarative_base
from lib.core.data import session
from sqlalchemy import Column, and_, or_, Integer, String, ForeignKey, text, DateTime, desc
from datetime import datetime
import time
import os

Base = declarative_base()


# 模型定义
class application_info_t(Base):
    __tablename__ = 'application_info_t'

    id = Column(Integer, primary_key=True)
    tid = Column(Integer)
    app_name = Column(String(255))
    app_version = Column(String(255))
    app_desc = Column(String(255))
    algorithm_mode = Column(Integer)
    begin_time = Column(DateTime, default=datetime.utcnow)
    end_time = Column(DateTime)
    app_state = Column(Integer)
    app_hash = Column(String(100))
    fuzz_addr = Column(Integer)
    platform = Column(Integer)
    instru_mode = Column(Integer)
    app_port = Column(Integer)
    iterations = Column(Integer)
    time_interval = Column(Integer)

    def __repr__(self):
        return '<app_name %r>' % self.app_name


class peach_pit(Base):
    __tablename__ = 'peach_pit'

    peach_id = Column(Integer, primary_key=True)
    pit_name = Column(String)
    pit_hash = Column(String)
    aid = Column(Integer)


class pit_test_t(Base):
    __tablename__ = 'pit_test_t'

    id = Column(Integer, primary_key=True)
    test = Column(String)
    test_status = Column(Integer)
    peach_id = Column(Integer, ForeignKey('peach_pit.peach_id'))


class pit_state_model_t(Base):
    __tablename__ = 'pit_state_model_t'

    id = Column(Integer, primary_key=True)
    state_model = Column(String)
    state_model_status = Column(Integer)
    test_id = Column(Integer, ForeignKey('pit_test_t.id'))


class pit_state_t(Base):
    __tablename__ = 'pit_state_t'

    id = Column(Integer, primary_key=True)
    state_name = Column(String)
    state_status = Column(Integer)
    state_model_id = Column(Integer, ForeignKey('pit_state_model_t.id'))
    action_count = Column(Integer)
    action_index = Column(Integer)


class sample_info_t(Base):
    __tablename__ = 'sample_info_t'
    sample_id = Column(Integer, primary_key=True)
    sample_name = Column(String(100))
    prefix_number = Column(Integer)
    suffix_number = Column(Integer)
    last_number = Column(Integer)
    format = Column(String(100))
    aid = Column(Integer)
    father_sample = Column(String(100))
    isexception = Column(Integer)
    sample_state = Column(Integer)
    taint_start = Column(String(100))
    taint_offset = Column(String(100))
    sample_hash = Column(String(100))
    state_id = Column(Integer)
    log_limit = Column(Integer)
    ins_limit = Column(Integer)
    action_index = Column(Integer)

    def __repr__(self):
        return '<sample_name %r>' % self.sample_name


class Partialnode(Base):
    __tablename__ = 'partial_node_t'
    nid = Column(Integer, primary_key=True)
    id = Column(Integer)
    tail = Column(Integer)
    parentnode = Column(Integer)
    status = Column(Integer)
    aid = Column(Integer)

    def __repr__(self):
        return '<id %r>' % self.id


# 外部调用的主函数
def changeIndex(appid=0, sleeptime=0, w=0):
    ''' appid: 要进行状态遍历的程序ID
    sleeptime: 执行下一个状态所需等待的时间
    逻辑: 根据用户上传的PeachPit文件进行状态遍历,当前状态在sleeptime秒内
    当前任务的覆盖率不变的情况下,自动遍历到下一个状态.
    '''
    app = session.query(application_info_t).filter_by(id=appid).first()

    if checkend(appid=appid):
        # 如果处在 SymE 模式下的 Fuzz阶段
        return

    # 获取当前任务是否为只跑FUZZING的状态
    is_fuzzing = None  # 当前任务是否为FUZZING的标记,用于区别符号执行的状态位
    if app.app_state == 5:
        is_fuzzing = True
    else:
        is_fuzzing = False

    ''' 一层一层往下遍历对应关系为:
        1个App 对应 多个peachpit（2017-1-12：可以对应多个peachpit，但是同一时间，只能使用一个peachpit）
            1个peachpit 对应 1个pittest
                1个pittest 对应 多个statemodel
                    1个statemode 对应 多个state
                        1个state 对应 多个action'''

    peachid = session.query(peach_pit).filter_by(aid=appid
                                                 ).order_by(desc(peach_pit.peach_id)).first().peach_id
    print "[-] This task use the peachpit_ID is %s" % (peachid)

    # 一个peachpit对应多个test
    testList = session.query(pit_test_t).filter(
        and_(or_(pit_test_t.test_status == 1, pit_test_t.test_status == 0),
             pit_test_t.peach_id == peachid)).all()
    for test in testList:
        test.test_status = 1
        session.commit()

        # 一个test对应多个statemodel
        stateModelList = session.query(pit_state_model_t).filter(
            and_(or_(pit_state_model_t.state_model_status == 1,
                     pit_state_model_t.state_model_status == 0),
                 pit_state_model_t.test_id == test.id
                 )).all()
        for sm in stateModelList:
            sm.state_model_status = 1
            session.commit()

            # 一个statemodel对应多个state
            stateList = session.query(pit_state_t).filter(
                and_(or_(pit_state_t.state_status == 1,
                         pit_state_t.state_status == 0),
                     pit_state_t.state_model_id == sm.id
                     )).all()
            # 特殊处理: statemodel的最后一个state不需要跑到最后一个状态
            stateListNotQuit = stateList
            # stateListQuit = stateList[-1:]
            # stateListQuit = []
            for state in stateListNotQuit:
                state.state_status = 1
                session.commit()

                # TODO: 状态遍历用于同步的等待记录
                # 为了避免用户在 状态遍历同步的过程中 关闭状态遍历进程 导致遍历进程的局部变量存储丢失
                # 进程会在等待同步之前,使用环境变量记录下当前状态数,如果判断其丢失则使用环境变量中的状态数
                if state.action_index > state.action_count:
                    if not os.environ.get('action_index'):
                        print '[*] action_index is null, now change the action_index = 1'
                        state.action_index = 1
                    else:
                        state.action_index = int(os.environ.get('action_index'))
                if w == 3:
                    state.action_index += 1
                    # 如果已经到达最后一个Action，还需要切换下一个状态，则是跳转至下一个State：
                    if state.action_index > state.action_count:
                        state.state_status = 2
                        session.commit()
                        continue
                # 状态遍历
                for current_index in range(state.action_index, state.action_count + 1):
                    changedbdata(currentState=state, currentindex=current_index,
                                 appid=appid, is_fuzzing=is_fuzzing, w=w)
                    oldCoveredNum = 0
                    newCoveredNum = 1
                    while newCoveredNum > oldCoveredNum:
                        oldCoveredNum = getCurrentCoverNum(appid=appid)
                        print '[-] begin sleep:' + time.strftime('%Y-%m-%d %H:%M:%S',
                                                                 time.localtime(time.time())) + '  duration:' + str(
                            sleeptime)
                        time.sleep(sleeptime)
                        print '[-] end sleep:' + time.strftime('%Y-%m-%d %H:%M:%S',
                                                               time.localtime(time.time())) + '  duration:' + str(
                            sleeptime)
                        newCoveredNum = getCurrentCoverNum(appid=appid)
                    w = 4  # 恢复正常:停当前Sample[0,1置3]，追加新Sample[0]流程
                state.state_status = 2
                session.commit()
                print '[-] Current pit_state is [%s] , be next one' % state.id
            sm.state_model_status = 2
            session.commit()
            print '[-] Current pit_state_model is [%s] , be next one' % sm.id
        test.test_status = 2
        session.commit()
        print '[-] Current pit_test is [%s] , be next one' % test.id

    # 如果跑完了所有状态则更改当前的算法为FUZZ
    print 'change the algorithm_mode to fuzzing !'
    sql = text('SELECT app_state from application_info_t WHERE id = :id;')
    data = session.execute(sql, {'id': appid}).fetchall()
    if len(data):
        app_state = data[0][0]
        if app_state == 1:
            sql_up = text('UPDATE application_info_t set algorithm_mode=4 WHERE id = :appid;')
            session.execute(sql_up, {'appid': appid})
            session.commit()
            return True


def checkend(appid=0):
    sql = text('SELECT app_state, algorithm_mode from application_info_t WHERE id = :id;')
    data = session.execute(sql, {'id': appid}).fetchall()
    if len(data):
        app_state = data[0][0]
        algorithm_mode = data[0][1]
        print '[*] GET task state:%s  algorithm_mode:%s' % (app_state, algorithm_mode)
        if app_state == 1 and algorithm_mode == 4:
            print '[*] Task state: Fuzz in SymE'
            return True
    return False


# 当前statemode的最后一个state不跑最后一个状态
# def changeIndexinQuitState(appid=0, stateListQuit=[], sleeptime=3 * 60, is_fuzzing=False):
#     '''当前的statemode的最后一个state的最后一个状态为"退出",是没有意义的'''
#     state = stateListQuit[0]
#     state.state_status = 1
#     session.commit()
#     if state.action_index > state.action_count:
#         if not os.environ.get('action_index'):
#             print '[*] action_index is null, now change the action_index = 1'
#             state.action_index = 1
#         else:
#             state.action_index = int(os.environ.get('action_index'))
#             # state.action_index = int(os.environ.get('action_index') or 1)
#     # action_index到action_count-1
#     for current_index in range(state.action_index, state.action_count):
#         changedbdata(currentState=state, currentindex=current_index, appid=appid, is_fuzzing=is_fuzzing)
#         oldCoveredNum = 0
#         newCoveredNum = 1
#         while newCoveredNum > oldCoveredNum:
#             oldCoveredNum = getCurrentCoverNum(appid=appid)
#             time.sleep(sleeptime)
#             newCoveredNum = getCurrentCoverNum(appid=appid)
#         print str(newCoveredNum) + ' = ' + str(oldCoveredNum)
#     state.state_status = 2
#     session.commit()


# 修改数据库
def changedbdata(currentState=None, currentindex=0, appid=0, is_fuzzing=False, w=0):
    '''实际执行状态遍历的函数,状态遍历的行为与数据库中体现'''
    # 记录当前状态
    os.environ['action_index'] = str(currentindex)
    print '[-] %s changedbdata Action_index: %s:%s' % (w, currentState.id, currentindex)
    # 符号执行的情况下,要等待求解端的龟速响应,所以我们需要同步一下状态
    if not is_fuzzing:

        # 停止当前peachpit_Action所对应的所有没有跑完的sample(3 手动切换下一状态 4 超时后，自动切换下一状态)
        if w in [2, 3, 4]:
            action_index_list = session.query(sample_info_t).filter(
                or_(sample_info_t.sample_state == 0, sample_info_t.sample_state == 1)
            ).filter_by(aid=appid).all()
            for action_index in action_index_list:
                action_index.sample_state = 3
            session.commit()
            print "[+] All sample.info stopped (change to 3)"
        else:
            print "[*] SymE mode: No sample.info stats need change"
        # 停止当前peachpit_Action所对应的所有没有跑完的sample

        # 符号执行的情况下,要等待分析、求解端的龟速响应,所以我们需要同步一下状态
        currentState.action_index = currentState.action_count + 1
        session.commit()
        while True:
            session.commit()
            if currentState.action_index == currentState.action_count + 3:
                break
            print '[-] Wait become %s, but now is %s' % (currentState.action_count + 3, currentState.action_index)
            time.sleep(3)
        print "[*] SymE mode: All right, Now, He has done it."

    if w in [2, 3, 4, 5]:
        # 根据最后的参数行生成新的sample_state为0的sample
        sample_general = session.query(sample_info_t).filter_by(aid=appid
                         ).filter_by(sample_state=6
                         ).order_by(desc(sample_info_t.sample_id)).first()
        new_sample = sample_info_t(
            sample_name=sample_general.sample_name,
            prefix_number=1, suffix_number=1, last_number=0,
            aid=sample_general.aid,
            isexception=sample_general.isexception,
            sample_state=0,
            log_limit=sample_general.log_limit,
            ins_limit=sample_general.ins_limit,
            taint_start=sample_general.taint_start,
            taint_offset=sample_general.taint_offset,
            sample_hash=sample_general.sample_hash,
            state_id=currentState.id,
            action_index=currentindex
        )
        currentState.action_index = currentindex
        session.add(new_sample)
        session.commit()
        print '[+] New sample are generated '
    else:
        print '[-] No sample.info data need add'


# 获取当前以覆盖的BBL数
def getCurrentCoverNum(appid=0):
    coverBblNum = session.query(Partialnode).filter_by(aid=appid) \
        .filter(or_(Partialnode.status == 1, Partialnode.status == 2)) \
        .count()
    return coverBblNum


# 2016.07.27 需求修改
# 该函数用于当用户设定总时间时，获取遍历次数以获取每次遍历所需的时间
def getTimeCount(appid=0):
    # appid: 要进行状态的遍历的程序ID
    timecount = 0
    peachid = session.query(peach_pit).filter_by(aid=appid
                                                 ).order_by(desc(peach_pit.peach_id)).first().peach_id
    testList = session.query(pit_test_t).filter(
        and_(or_(pit_test_t.test_status == 0,
                 pit_test_t.test_status == 1,
                 pit_test_t.test_status == 2),
             pit_test_t.peach_id == peachid)).all()
    for test in testList:
        stateModelList = session.query(pit_state_model_t).filter(
            and_(or_(pit_state_model_t.state_model_status == 0,
                     pit_state_model_t.state_model_status == 1,
                     pit_state_model_t.state_model_status == 2),
                 pit_state_model_t.test_id == test.id
                 )).all()
        for sm in stateModelList:
            stateList = session.query(pit_state_t).filter(
                and_(or_(pit_state_t.state_status == 0,
                         pit_state_t.state_status == 1,
                         pit_state_t.state_status == 2),
                     pit_state_t.state_model_id == sm.id
                     )).all()
            stateListNotQuit = stateList[:-1]
            stateListQuit = stateList[-1:]
            for state in stateListNotQuit:
                for current_index in range(1, state.action_count + 1):  # state.action_index
                    timecount = timecount + 1
            for state in stateListQuit:
                for current_index in range(1, state.action_count + 1):  # state.action_index
                    timecount = timecount + 1
    return timecount
