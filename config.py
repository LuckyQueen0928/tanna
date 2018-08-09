# -*- coding: utf-8 -*-

import os
basedir = os.path.abspath(os.path.dirname(__file__))


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'the_antman_web_secret_key_Xo454@adfd'
    SQLALCHEMY_COMMIT_ON_TEARDOWN = True

    FILENAME_TIMEFORMAT = '%Y%m%d%H%M%S'
    SSH_SESSION = None
    AW_TASKLIST_PER_PAGE = os.environ.get('AW_TASKLIST_PER_PAGE') or 10  # 任务列表每页显示的作品
    SAMPLE_NAME_PREFIX = 'sample'
    AYE_FAIL = '该地址已在翻转队列，请勿重复提交'.decode('utf-8')
    AYE_SUCCESS = '该地址以添加到路径翻转队列，正在等待翻转'.decode('utf-8')

    NFS_FOLDER = os.environ.get('NFS_FOLDER') or '/usr/local/nfs/'  # 网络驱动器的本地路径，共享目录根目录

    ADDR_FOLDER = os.environ.get('ADDR_FOLDER') or 'addr/'                # 存放 addr地址文件，nbp端产生
    ASSIST_FOLDER = os.environ.get('ASSIST_FOLDER') or 'assist/'          # 存放 assist污点范围标记文件，nbp端产生
    CONFIG_FOLDER = os.environ.get('CONFIG_FOLDER') or 'config/'          # 存放 文档类测试文件
    CONSTRAIN_FOLDER = os.environ.get('CONFIG_FOLDER') or 'constrain/'    # 存放 约束范式文件，nba生成
    EXP_FOLDER = os.environ.get('EXP_FOLDER') or 'exception/'             # 存放 异常文件
    EXEC_FOLDER = os.environ.get('EXEC_FOLDER') or 'exec/'                # 存放 目标程序的主程序，nbp端ssh获取
    HOOK_FOLDER = os.environ.get('HOOK_FOLDER') or 'hook/'                # 存放 hook函数，用户提交，web产生

    MAP_FOLDER = os.environ.get('MAP_FOLDER') or 'map/'                   # 存放 map文件，nbp端产生
    PASS_FOLDER = os.environ.get('PASS_FOLDER') or 'pass/'                #
    PIT_FOLDER = os.environ.get('PIT_FOLDER') or 'pit/'                   # 存放 peachpit测试套，用户上传的zip包
    RESULT_FOLDER = os.environ.get('RESULT_FOLDER') or 'result/'          # 存放 结果文件，需永久保存

    SAMPLE_FOLDER = os.environ.get('SAMPLE_FOLDER') or 'sample/'          # 存放 样本文件，需永久保存
    SOURCE_FOLDER = os.environ.get('SOURCE_FOLDER') or 'source/'          # 存放 目标程序源代码，用户上传的zip包
    SYM_FOLDER = os.environ.get('SYM_FOLDER') or 'symbolic/'              #
    TRACE_FOLDER = os.environ.get('TRACE_FOLDER') or 'trace/'             # 存放 Trace文件，nbp端产生
    # 现在判断程序架构的方式，需要更换
    X64_FOLDER = os.environ.get('X64_FOLDER') or 'x64/'
    # 文档类新增的目录
    XML_FOLDER = os.environ.get('XML_FOLDER') or 'xml/'                   # 存放上传的xml文件
    PROCESS_FOLDER = os.environ.get('PROCESS_FOLDER') or 'process/'       # 存放上传的待测文件
    AW_DIR_LIST = [ADDR_FOLDER, ASSIST_FOLDER, CONFIG_FOLDER, CONSTRAIN_FOLDER, EXP_FOLDER, EXEC_FOLDER, HOOK_FOLDER,
                   MAP_FOLDER, PASS_FOLDER, PIT_FOLDER, RESULT_FOLDER,
                   SAMPLE_FOLDER, SOURCE_FOLDER, SYM_FOLDER, TRACE_FOLDER, X64_FOLDER, PROCESS_FOLDER, XML_FOLDER]# --文档类

    @staticmethod
    def init_app(app):
        pass


class DevelopmentConfig(Config):
    DEBUG = True
    TESTING = True
    NFS_FOLDER = os.environ.get('NFS_FOLDER') or'/usr/local/nfs/'  # 网络驱动器的本地路径

    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
            'mysql+pymysql://root:LYS1105Tz@localhost:3306/antweb2?charset=utf8'
        # 'sqlite:///' + os.path.join(basedir, 'data-dev.sqlite')
    #WAIT_TIME_SEC = os.environ.get('WAIT_TIME_SEC')


class TestingConfig(Config):
    DEBUG = True
    TESTING = True
    NFS_FOLDER = os.environ.get('NFS_FOLDER') or'/usr/local/nfs/' 
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'mysql+pymysql://root:123456@192.168.1.129/test2.0'
    #WAIT_TIME_SEC = os.environ.get('WAIT_TIME_SEC')


class ProductionConfig(Config):
    DEBUG = True
    TESTING = True
    NFS_FOLDER = os.environ.get('NFS_FOLDER') or '/usr/local/nfs/'  # 网络驱动器的本地路径
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'mysql+pymysql://root:123456@192.168.1.129/test'
    #WAIT_TIME_SEC = os.environ.get('WAIT_TIME_SEC')


config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
