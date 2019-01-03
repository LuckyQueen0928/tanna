# -*- coding: utf-8 -*-

import os
import shutil
import sys
import math
from . import main
from flask import (
    render_template,
    session,
    redirect,
    url_for,
    current_app,
    request,
    Response,
    jsonify,
    make_response,
    session,
    send_from_directory
)
from lib.core.processIndexd import changedbdata, changeIndex
from ..models import (
    indextasklist,
    application_info_t,
    Globalnode,
    Globaledge,
    Partialedge,
    Partialnode,
    peach_pit,
    sample_info_t,
    sensitive_addr_info,
    sensitive_post_t,
    source_asm_map,
    special_node_t,
    task_info_t,
    w_task_info_t,
    trace_info_t,
    User,
    constrain_info_t,
    coverage_log_t
)
from sqlalchemy import or_, and_, desc
from lib.core.special import unzip
from lib.core.special import repitname
from lib.core.special import get_filename_from_path
from lib.core.handle_pit import HandlePeachPit
from lib.core.data import logprocesslist
from lib.core.data import indexprocesslist
from app.features.views import stopLogProcess, stop_index_process, stop_log_process, start_index_process, \
    start_log_process, startIndexTraversalProcess
from app.features.views import stopIndexTraversalProcess
from app.features.views import startProcess
from lib.core.ssh2pin import get_file_list, sftp_download_file, sftp_upload_file, ssh_connect, create_file_onssh
from ..xmltodb import read_xml, write_xml, find_nodes, if_match, get_node_by_keyvalue, change_node_properties, change_node_text
import ntpath
import xml.etree.ElementTree as ET

from app import db
# 取得本地文件 
from werkzeug.datastructures import FileStorage

# 使用utf-8编码
reload(sys)
sys.setdefaultencoding('utf-8')


# 检测用户是否登录
@main.before_app_request
def before_request():
    try:
        is_auth = session['auth']
    except Exception, e:
        is_auth = False
    if not is_auth and request.endpoint != 'auth.login' \
                   and request.endpoint != 'auth.regedit' \
                   and request.endpoint != 'static':
        return redirect(url_for('auth.login'))


# 登录导航界面并设置为默认首页
@main.route('/')
def login_guide():
    return render_template('auth/login_guide.html')


# 主页兼任务列表页面
@main.route('/index', methods=['GET', 'POST'])
def index():
    page = request.args.get('page', 1, type=int)
    page = 1 if page < 1 else page
    pagination = indextasklist.query.order_by(
        indextasklist.tid.desc()).paginate(
        page, per_page=current_app.config['AW_TASKLIST_PER_PAGE'] or 10, error_out=False)
    count = indextasklist.query.count()
    tasklist = pagination
    end_page = float(count) / current_app.config['AW_TASKLIST_PER_PAGE']
    if len(indexprocesslist) > 0:
        pass
    else:
        startProcess(timeout=0, whoneed=1)
    # TODO 判定界面传来的move值是否为1，若为1，匹配出与数据库中不同的文件，并将其移动到extra文件夹中  
    if request.method == 'POST':
        move = request.form['move']
        if move == "1":
            # 查询并移动文件
            search_diff_nfs_task()
            return jsonify({'status': 1, 'msg': '文件移动成功！'})
    return render_template(
        'index.html', title='Home', tasklist=tasklist,
        tasknum=0, page=page, end_page=int(math.ceil(end_page)), count=count
    )


def search_diff_nfs_task():
    # 匹配出共享目录和数据库中不同的目录 ，并将这些目录移入extra文件夹中  
    task_hash1 = w_task_info_t.query.all()
    task_hash2 = task_info_t.query.all()
    task_hash = []
    for task in task_hash1:
        task_hash.append(task.task_hash)
    for task in task_hash2:
        task_hash.append(task.task_hash)
    # 列出共享目录中的文件列表
    nfs_files = os.listdir(current_app.config['NFS_FOLDER'])
    # 找出两个目录不一致的文件
    tmps = list(set(nfs_files).difference(set(task_hash)))
    if len(tmps) > 0:
        # 判定共享目录里面是否有extra文件夹，如果存在，删除，如果不存在就新建
        if "extra" in tmps:
            tmps.remove("extra")
        else:
            os.mkdir(current_app.config['NFS_FOLDER'] + "extra")
        if len(tmps) > 0:
            for tmp in tmps:
                filepath = os.path.join(current_app.config['NFS_FOLDER'], tmp)
                newpath = os.path.join(current_app.config['NFS_FOLDER'], 'extra')
                shutil.move(filepath, newpath + "/" + tmp)
                # 删除指定路径下的文件
                #     shutil.rmtree(filepath)


# 新建任务页面，任务名及任务描述
@main.route('/newtask/', methods=['GET', 'POST'])
def newtask():
    if request.method == 'POST':
        taskname = request.form['taskname']
        taskinfo = request.form['taskinfo']
        if taskname == '':
            return render_template(
                'message.html', message="任务名不能为空!".decode('utf-8')
            )
        resp = make_response(redirect(url_for('.net_upload')))
        resp.set_cookie('new_task_name', taskname)
        resp.set_cookie('new_task_info', taskinfo)
        return resp
    return render_template(
        'newtask.html', title='Newtask'
    )


# 删除任务页面
@main.route('/deletetask/', methods=['POST'])
def deletetask():
    if request.method == 'POST':
        taskid = int(request.form['taskid'])
        task = task_info_t.query.filter_by(tid=taskid).first()
        app = application_info_t.query.filter_by(tid=taskid).first()
        # 删除表中数据
        application_info_t.query.filter_by(tid=taskid).delete()
        constrain_info_t.query.filter_by(aid=app.id).delete()
        coverage_log_t.query.filter_by(aid=app.id).delete()
        Globaledge.query.filter_by(aid=app.id).delete()
        Globalnode.query.filter_by(aid=app.id).delete()
        Partialedge.query.filter_by(aid=app.id).delete()
        Partialnode.query.filter_by(aid=app.id).delete()
        peach_pit.query.filter_by(aid=app.id).delete()
        sample_info_t.query.filter_by(aid=app.id).delete()
        sensitive_addr_info.query.filter_by(aid=app.id).delete()
        sensitive_post_t.query.filter_by(aid=app.id).delete()
        source_asm_map.query.filter_by(aid=app.id).delete()
        special_node_t.query.filter_by(aid=app.id).delete()
        task_info_t.query.filter_by(tid=taskid).delete()
        trace_info_t.query.filter_by(aid=app.id).delete()
        # 删除共享目录中对应的目录
        hash_dirname = task.task_hash
        try:
            db.session.commit()
        except Exception, e:
            print str(e)
            return jsonify({'status': 0, 'msg': 'Failure！'})
        import shutil
        try:
            shutil.rmtree(gettaskpath(hash_dirname))
        except Exception, e:
            print str(e)
            pass
        return jsonify({'status': 1, 'msg': '任务删除成功！'})


# 文件上传页面
# 该页面会新建任务所需的文件夹，因为架构原因文件会上传到已经挂载的共享目录
@main.route('/newtask/net-upload', methods=['GET', 'POST'])
def net_upload():
    if request.method == 'POST':
        source_zip = request.files['source-zip']
        peachpit = request.files['peachpit']
        hookcontent = request.form['hook-up']
        hooktext2file = open(u'function.txt', 'w')
        hooktext2file.writelines(hookcontent.encode("UTF-8"))
        hooktext2file.close()
        hookfile = FileStorage(open(u'function.txt', 'r'), content_type='text/plain')
        if peachpit:
            # 上传四个文件
            try:
                hash_dirname = uploadfile(
                    source_zip=source_zip,
                    peachpit=peachpit,
                    symbolic=None,
                    hookfile=hookfile
                )
            except Exception as e:
                print '[!] ', str(e)
                e_info = str(e)
                return render_template(
                    'message.html',
                    message=e_info.decode('utf-8')
                )
            resp = make_response(redirect(url_for('.ssh_login')))
            resp.set_cookie('task_hash', hash_dirname)
            resp.set_cookie('source_zip', source_zip.filename)
            resp.set_cookie('peachpit', peachpit.filename)
            resp.set_cookie('hook_content', hookcontent)
            return resp
        else:
            return render_template(
                'message.html',
                message='待测程序和peachpit文件不可为空，请上传zip文件！'.decode('utf-8')
            )
    return render_template(
        'net-upload.html'
    )


# ssh-login页面
# 该页面需要输入目标主机的ip地址、端口号、用户名和密码
@main.route('/newtask/ssh-login', methods=['GET', 'POST'])
def ssh_login():
    if request.method == 'POST':
        ipaddr = request.form.get("ipaddress")
        port = request.form.get("port")
        username = request.form.get("username")
        password = request.form.get("password")
        try:
            current_app.config['SSH_SESSION'] = ssh_connect(ipaddr, int(port), username, password)
            resp = make_response(redirect(url_for('.ssh_filelist')))
            resp.set_cookie('ipaddress', ipaddr)
            resp.set_cookie('username', username)
            resp.set_cookie('password', password)
            return resp
            return redirect(url_for('.ssh_filelist'))
        except Exception, e:
            # TODO: 新需求，暂时不知道会出现什么异常，所以先输出原本的异常信息以便调试
            return render_template(
                'message.html',
                message=str(e).decode('utf-8')
            )
    return render_template('ssh-login.html')


@main.route('/newtask/ssh-filelist', methods=['GET', 'POST'])
def ssh_filelist():
    if request.method == 'POST':
        filepath = request.form.get('filepath')
        print filepath
        config_nbp_path = '/Nbitsec/nbp/config_nbp.ini'
        filename = get_filename_from_path(filepath)
        taskhash = request.cookies.get('task_hash')
        execpath = getfeaturepath_by_cookie('EXEC_FOLDER') + filename
        mappath = getfeaturepath_by_cookie('MAP_FOLDER') + 'map_' + taskhash
        x64path = getfeaturepath_by_cookie('X64_FOLDER') + 'x64'
        hook_config_nbp_path = getfeaturepath_by_cookie('HOOK_FOLDER') + 'config_nbp.ini'
        hook_func = taskhash + '.txt'
        hook_content_path = getfeaturepath_by_cookie('HOOK_FOLDER') + hook_func
        try:
            # 在ssh端生成文件
            createfile = create_file_onssh(current_app.config['SSH_SESSION'], filepath, config_nbp_path)
            # 下载文件到共享目录下约定的目录：程序文件 map文件 x64文件 pintool配置文件
            sftp_download_file(current_app.config['SSH_SESSION'], filepath, execpath)
            sftp_download_file(current_app.config['SSH_SESSION'], '/tmp/antman_pin_map', mappath)
            sftp_download_file(current_app.config['SSH_SESSION'], '/tmp/antman_pin_x64', x64path)
            sftp_download_file(current_app.config['SSH_SESSION'], config_nbp_path, hook_config_nbp_path)
            sftp_upload_file(current_app.config['SSH_SESSION'], hook_content_path, '/Nbitsec/nbp/function.txt')
            # 根据前端获得的ssh信息以及上传的xml文件，更新peachpit的xml配置信息：ssh端的ip地址，账号，密码
            username = request.cookies.get('username')
            ip = request.cookies.get('ipaddress')
            password = request.cookies.get('password')
            task_dirpath = request.cookies.get('task_hash')
            ftp_fuzzing_xml_path = os.path.join(current_app.config['NFS_FOLDER'], task_dirpath,
                                                current_app.config['PIT_FOLDER'], task_dirpath, 'Net/ftp_fuzzing.xml')
            ftp_fuzzing_xmlconfig_path = os.path.join(current_app.config['NFS_FOLDER'], task_dirpath,
                                                      current_app.config['PIT_FOLDER'], task_dirpath, 'Net/ftp_fuzzing.xml.config')
            parameters = '{http://peachfuzzer.com/2012/Peach}Agent/{http://peachfuzzer.com/2012/Peach}Monitor/{http://peachfuzzer.com/2012/Peach}Param'
            auto_update_xmldatas(ftp_fuzzing_xml_path, parameters, 'name', 'Username', username)
            auto_update_xmldatas(ftp_fuzzing_xml_path, parameters, 'name', 'Password', password)
            auto_update_xmldatas(ftp_fuzzing_xmlconfig_path, 'All/Ipv4', 'key', 'TargetIPv4', ip)
        except Exception, e:
            # TODO: 新需求，暂时不知道会出现什么异常，所以先输出原本的异常信息以便调试
            return render_template(
                'message.html',
                message=str(e).decode('utf-8')
            )
        if os.path.exists(execpath) and os.path.exists(mappath) and os.path.exists(x64path):
            if os.path.getsize(x64path):
                platform = 1
            else:
                platform = 0
            resp = make_response(redirect(url_for('.net_config')))
            hash_dirname = request.cookies.get('task_hash')
            resp.set_cookie('plat_form', str(platform))
            resp.set_cookie('app_name', filename)
            resp.set_cookie('app_fullpath', filepath)
            resp.set_cookie('app_hash_name', getfilename(hash_dirname, filename))
            return resp
        else:
            return render_template(
                'message.html',
                message='生成失败请重新选择文件地址'.decode('utf-8')
            )
    # TODO: 新需求，该功能会产生任意文件遍历，但是是要求没办法...
    dirpath = request.args.get('path') or '/'
    dirsplit = filter(None, dirpath.split('/'))
    if '/'.join(dirsplit[:-1]) == '':
        fatherpath = '/' + '/'.join(dirsplit[:-1])
    else:
        fatherpath = '/' + '/'.join(dirsplit[:-1]) + '/'
    filelist = get_file_list(current_app.config['SSH_SESSION'], dirpath)
    return render_template(
        'ssh-filelist.html',
        filelist=filelist,
        current_path=dirpath,
        fatherpath=fatherpath,
        rootpath='/'
        )


# 任务配置页面
# 该页面会创建任务并写入数据库
@main.route('/newtask/net-config', methods=['GET', 'POST'])
def net_config():
    if request.method == 'POST':
        config_dict = {
            "module": request.cookies.get("app_hash_name"),
            "log": 0,
            "loglimit": request.form['loglimit'],
            "ins": request.form['ins'],
            "taint_offset_start": request.form['taint_offset_start'],
            "taint_offset": request.form['taint_offset'],
            # "timeout" : request.form['timeout'],
            # "action_count" : request.form['action_count'],
            "case_count": request.form['case_count'],
            "app_status": request.form['app_status'],
            # "platform": request.form['platform'],
            "stubmode": request.form['stubmode'],
            "peach_test": request.form['peach_test'],
            'app_port': request.form['port_num']
        }
        hash_dirname = request.cookies.get('task_hash')
        port = request.form['port_num']
        # 根据用户所提交的数据，填写数据库记录
        create_task_in_database(config_dict=config_dict)
        # 修改ftp_fuzzing_xml.config中的端口号
        ftp_fuzzing_xmlconfig_path = os.path.join(current_app.config['NFS_FOLDER'], hash_dirname,
                                                  current_app.config['PIT_FOLDER'], hash_dirname,
                                                  'Net/ftp_fuzzing.xml.config')
        auto_update_xmldatas(ftp_fuzzing_xmlconfig_path, 'All/Range', 'key', 'TargetPort', port)

        # 所有工作准备就绪，更新当前任务为正在运行的任务，并停止其它任务，因为某agent的只能跑单任务( ´_ゝ｀)
        update_task_state(taskid=session.get('taskid'))
        return redirect(url_for('.net_creating'))
    return render_template('net-config.html',
                           htmltaskname=request.cookies.get('new_task_name'),
                           htmltaskinfo=request.cookies.get('new_task_info'),
                           htmlfullpath=request.cookies.get('app_fullpath'),
                           htmlsourcezip=request.cookies.get('source_zip'),
                           htmlpeachpit=request.cookies.get('peachpit'),
                           htmlipaddress=request.cookies.get('ipaddress'),
                           htmlplatform=request.cookies.get('plat_form'),
                           htmlhook=request.cookies.get('hook_content')
                           )


# 等待生成预处理端生成函数信息
@main.route('/newtask/net-creating', methods=['GET'])
def net_creating():
    return render_template('task-creating.html')


# 根据函数信息生成黑名单列表
@main.route('/newtask/blackfunclist/', methods=['GET'])
def blackfunclist():
    appid = session.get('appid')
    gnodelist = Globalnode.query.filter_by(aid=appid).limit(200).all()
    return render_template('exchangefun.html', gnodelist=gnodelist)


# 等待预处理全部完成
@main.route('/newtask/pre/', methods=['GET', 'POST'])
def taskpre():
    appid = session.get('appid')
    taskid = application_info_t.query.filter_by(id=appid).first().tid
    # 原本创建遍历进程是在主界面完成的，但是每次进入主界面都会导致遍历进程重启。
    timeout = application_info_t.query.filter_by(id=appid).first().time_interval
    startProcess(timeout=timeout, whoneed=2)
    return render_template('taskpre.html', taskid=taskid)


# 接收黑名单的ajax提交
@main.route('/newtask/blackfunclist/post/', methods=['POST'])
def postblackfunc():
    appid = session.get('appid')
    funcList = request.json['funclist']
    submit_count = request.json['sc']
    msgDict = {'status': 1, 'msg': '黑名单' + str(submit_count) + '已提交'}
    for func in funcList:
        gn = Globalnode.query.filter_by(id=int(func, 16)
                                        ).filter_by(aid=appid).first()
        gn.check_flag = int(submit_count)
    db.session.commit()
    return jsonify(msgDict)


# 中间重定向页面，如果客户提交0，app_status修改为4，如果提交6，app_status修改为7
# 4 : 黑名单提交完毕，等待预处理
@main.route('/newtask/func-change-over/', methods=['GET'])
def funcchange():
    appid = session.get('appid')
    appstatue = session.get('appstate')
    app = application_info_t.query.filter_by(id=appid).first()
    if appstatue == 0:
        app.app_state = 4
        db.session.commit()
        print'[+] Change app_state: From 0 to 4'
    elif appstatue == 6:
        app.app_state = 7
        print'[+] Change app_state: From 6 to 7'
        db.session.commit()
    return redirect(url_for('main.taskpre'))


# ajax，用于检查任务状态，当前负责两个状态的检查
# 1. taskcreated : 任务配置之后，检查函数是否生成
# 2. pre ： 黑名单列表上传结束之后，检查预处理是否结束，并生成当前任务信息
@main.route('/newtask/check/<checktype>', methods=['get'])
def checking(checktype=''):
    appid = session.get('appid')
    msg = ''
    if checktype == 'taskcreated':
        app_state = application_info_t.query.filter_by(id=appid).first().app_state
        func_count = Globalnode.query.filter_by(aid=appid).count()
        if func_count:
            msg = u'[*] 已生成函数信息数据，总共%s条!' % str(func_count)
        else:
            msg = u'[*] 正在生成函数信息数据，如果程序包含比较多的函数，这将会等待比较长的时间！'
        return jsonify({'status': app_state, 'msg': msg})
    if checktype == 'pre':
        app_state = application_info_t.query.filter_by(id=appid).first().app_state
        if app_state is not 1:
            msg = u'[*] 正在处理黑名单。'
            pcount = Partialnode.query.filter_by(aid=appid).count()
            sam_count = source_asm_map.query.filter_by(aid=appid).count()
            if pcount and not sam_count:
                msg = u'[*] 已生成BBL数据，总共%s个！' % str(pcount)
            if sam_count and pcount:
                msg = u'[*] 已生成源码及汇编信息%s条！' % str(sam_count)
        return jsonify({'status': app_state, 'msg': msg})


# 从主页查看任务
@main.route('/opentask/taskid-<taskid>', methods=['get'])
def opentask(taskid):
    # 根据传入taskid获取并设置系统主索引
    app = application_info_t.query.filter_by(tid=taskid).first()
    appid = app.id
    session['taskid'] = taskid
    session['appid'] = appid

    # 当预处理处理没有结束的时候返回到预处理环节
    if app.app_state == 0 or app.app_state == 6:
        return redirect(url_for('main.net_creating'))
    if app.app_state == 3:
        return redirect(url_for('main.blackfunclist'))
    if app.app_state == 4 or app.app_state == 7:
        return redirect(url_for('main.taskpre'))
    if app.app_state == 1 or app.app_state == 5:
        return redirect(url_for('features.featmain'))


# 开启任务的重定向页面开启当前任务并关闭其它任务，原因同上;( ´_ゝ｀)
# 该页面会将当前任务ID和当前任务所对应的程序ID写入session中
# 响应主界面 开启任务 按钮操作
@main.route('/opentask_contral/taskid-<taskid>', methods=['get'])
def opentask_contral(taskid):
    # 根据传入taskid获取并设置系统主索引
    app = application_info_t.query.filter_by(tid=taskid).first()
    appid = app.id
    session['taskid'] = taskid
    session['appid'] = appid

    update_task_state(taskid=taskid)

    # 当预处理处理没有结束的时候返回到预处理环节
    if app.app_state == 0 or app.app_state == 6:
        return redirect(url_for('main.net_creating'))
    if app.app_state == 3:
        return redirect(url_for('main.blackfunclist'))
    if app.app_state == 4 or app.app_state == 7:
        return redirect(url_for('main.taskpre'))
    if app.app_state == 1 or app.app_state == 5:
        # 首页从暂停状态恢复任务，需要以SSH的方式更新PIN端的配置信息（hook文件 config_nbp.ini文件）
        task_hash = app.app_hash
        pit_hash = peach_pit.query.filter_by(aid=appid).order_by(peach_pit.peach_id).first().pit_hash
        read_ftp_fuzzing_xml_path = os.path.join(current_app.config['NFS_FOLDER'], task_hash,
                                                 current_app.config['PIT_FOLDER'], pit_hash, 'Net/ftp_fuzzing.xml')
        read_ftp_fuzzing_xmlconfig_path = os.path.join(current_app.config['NFS_FOLDER'], task_hash,
                                                       current_app.config['PIT_FOLDER'], pit_hash,
                                                       'Net/ftp_fuzzing.xml.config')
        hook_path = os.path.join(current_app.config['NFS_FOLDER'], task_hash, 'hook/', task_hash, '.txt')
        ssh_file_path = os.path.join(current_app.config['NFS_FOLDER'], task_hash, 'hook/', 'config_nbp.ini')
        update_ssh_file(read_ftp_fuzzing_xml_path, read_ftp_fuzzing_xmlconfig_path, hook_path, ssh_file_path)
        print 'Switch task success'
        return redirect(url_for('features.featmain'))


# 关闭任务
@main.route('/task/shutdown/', methods=['get', 'post'])
def shutdownTask():
    json = {'status': 0, 'msg': ''}
    taskid = request.form['tasknum']
    try:
        t = task_info_t.query.filter_by(tid=int(taskid)).first()
        t.task_state = 1
        db.session.commit()
        json['status'] = 1
        stopIndexTraversalProcess()
        stopLogProcess()
        json['msg'] = '成功关闭了该任务！'
        return jsonify(json)
    except Exception, e:
        print str(e)
        json['msg'] = '关闭任务执行失败！'
        return jsonify(json)


# ;( ´_ゝ｀)
def update_task_state(taskid=0):
    '''开启当前任务并关闭存在与数据库中的其它任务
    任务状态（task_info_t.task_state）为0时表示该任务正在运行,为1表示该任务停止。
    该函数主要是配合某端只能跑单任务的情况;( ´_ゝ｀)
    '''
    task = task_info_t.query.filter_by(tid=taskid).first()
    task.task_state = 0
    othertasks = task_info_t.query.filter(task_info_t.tid != taskid).all()
    for othertask in othertasks:
        othertask.task_state = 1
    db.session.commit()
    print '[+] Stop other task success, current task Ready~'


# 2016.12.13修改pin端文件
def update_ssh_file(read_ftp_fuzzing_xml_path='', read_ftp_fuzzing_xmlconfig_path='', hook_path='', ssh_file_path=''):
    try:
        parameters = '{http://peachfuzzer.com/2012/Peach}Agent/{http://peachfuzzer.com/2012/Peach}Monitor/{http://peachfuzzer.com/2012/Peach}Param'
        # 获取ftp_fuzzing_xml中ssh登录信息
        username = read_xmldatas(read_ftp_fuzzing_xml_path, parameters, 'name', 'Username')
        password = read_xmldatas(read_ftp_fuzzing_xml_path, parameters, 'name', 'Password')
        ip = read_xmldatas(read_ftp_fuzzing_xmlconfig_path, 'All/Ipv4', 'key', 'TargetIPv4')
        current_app.config['SSH_SESSION'] = ssh_connect(ip, 22, username, password)
        save_path = '/Nbitsec/nbp/'
        sftp_upload_file(current_app.config['SSH_SESSION'], hook_path, save_path + 'function.txt')
        sftp_upload_file(current_app.config['SSH_SESSION'], ssh_file_path, save_path + 'config_nbp.ini')
        print "update files in nbf and nbp successfully! [xml's ssh info, nbp's config file, hookfile]"
    except Exception, e:
        # raise e
        # TODO: 新需求，暂时不知道会出现什么异常，所以先输出原本的异常信息以便调试
        return render_template(
            'message.html',
            message=str(e).decode('utf-8')
        )


# 文件上传
def uploadfile(source_zip, peachpit, symbolic, hookfile):
    '''任务上传函数
    传入的五个参数都是flask的文件对象
    并返回当前任务的唯一值路径
    '''
    # 使用gettaskownstr生成匹配任务的唯一值字符串
    taskhash = gethash(request.cookies.get('new_task_name'))
    hash_dirname = gettaskownstr(taskhash)
    taskpath = gettaskpath(hash_dirname=hash_dirname)  # 获取当前任务路径
    # 根据配置文件config.py的列表，创建任务所需的文件夹
    create_dir_by_list(
        bashpath=taskpath,
        dirlist=current_app.config['AW_DIR_LIST']
    )
    # TODO：更改当前文件夹权限，临时解决其它处理端没有权限读取文件的情况
    # os.system('sudo chmod 777 -R ' + taskpath)
    save_file(source_zip, taskpath, 'SOURCE_FOLDER', hash_dirname)
    pp_file = save_file(peachpit, taskpath, 'PIT_FOLDER', hash_dirname)
    save_file(hookfile, taskpath, 'HOOK_FOLDER', hash_dirname)
    unzippath = os.path.join(taskpath, current_app.config['PIT_FOLDER'])
    # 需求修改，新的peachpit文件由xml转为zip压缩文件，并需要解压及重命名
    unzip(pp_file, unzippath)
    repitname(unzippath, hash_dirname)
    session['unzippath'] = unzippath
    return hash_dirname

# 新增第3阶段,结果合并处理
@main.route('/Incremental/', methods=['GET', 'POST'])
def Incremental():
    appid = session.get('appid')
    taskid = application_info_t.query.filter_by(id=appid).first().tid
    app_port = application_info_t.query.filter_by(id=appid).first().app_port
    # TODO 断点续测页面取出原始数据   ---by cmf
    instru_mode = application_info_t.query.filter_by(id=appid).first().instru_mode
    app_state = application_info_t.query.filter_by(id=appid).first().app_state
    sample_info = sample_info_t.query.filter_by(aid=appid, sample_state=6
                                                ).order_by(desc(sample_info_t.sample_id)).first()
    log_limit = sample_info.log_limit
    ins_limit = sample_info.ins_limit
    taint_start = sample_info.taint_start
    taint_offset = sample_info.taint_offset
    case_count = peach_pit.query.filter_by(aid=appid).first().case_count
    peach_test = peach_pit.query.filter_by(aid=appid).first().pit_name
    hash_dirname = application_info_t.query.filter_by(id=appid).first().app_hash
    hookfile_path = os.path.join(current_app.config['NFS_FOLDER'], hash_dirname, current_app.config['HOOK_FOLDER'],
                                 hash_dirname + ".txt")
    hookfile_content = open(hookfile_path, "r")
    hook_up = hookfile_content.read()
    hookfile_content.close()

    if request.method == 'POST':
        # 获取app_state表单，放入session【app_state】中，用作黑名单提交后的 SymE 或 Fuzz 流程控制依据--zhy
        session['app_status'] = request.form['app_status']
        app = application_info_t.query.filter_by(id=appid).first()
        hash_dirname = app.app_hash
        taskpath = gettaskpath(hash_dirname=hash_dirname)
        hash_dirname = str(hash_dirname[:-14]) + getnow()
        # 2016.12.28 获取表单上的hook和peachpit并上传nfs--zhy
        hook_func = hash_dirname + '.txt'
        hooktext2file = open(hook_func, 'w')
        hooktext2file.writelines((request.form['hook']).encode("UTF-8"))
        hooktext2file.close()
        hookfile = FileStorage(open(hook_func, 'r'), content_type='text/plain')
        save_file(hookfile, taskpath, 'HOOK_FOLDER', hash_dirname)
        peachpit_info = request.files.get('peachpit')
        pp_file = save_file(peachpit_info, taskpath, 'PIT_FOLDER', hash_dirname)
        unzippath = os.path.join(taskpath, current_app.config['PIT_FOLDER'])
        # 新增sample_info_t数据--zhy
        sampleinfo = sample_info_t(
            sample_name=current_app.config['SAMPLE_NAME_PREFIX'],
            prefix_number=1, suffix_number=1, last_number=0,
            aid=app.id, isexception=0,
            sample_state=6,  # this sample is not running
            taint_start=request.form.get('taint_offset_start'),
            taint_offset=request.form.get('taint_offset'),
            sample_hash=hash_dirname,
            log_limit=request.form.get('loglimit'),
            ins_limit=request.form.get('ins'),
            action_index=1
        )
        # 新增application_info_t数据--zhy
        port = request.form.get('port_num')
        if port != app_port:
            app = application_info_t.query.filter_by(id=appid).first()
            app.app_port = port
            app.instru_mode = request.form.get('stubmode')
            app.app_state = 3
            db.session.add(app)
        db.session.add(sampleinfo)
        db.session.commit()
        print '[+] Add new sample(state:6)'
        # 需求修改，新的peachpit文件由xml转为zip压缩文件，并需要解压及重命名
        unzip(pp_file, unzippath)
        path = unzippath + '/' + "ftp_fuzzing"
        newname = unzippath + '/' +hash_dirname
        if os.path.isdir(path):
            try:
                os.rename(path, newname)
            except OSError, e:
                shutil.rmtree(newname)
                os.rename(path, newname)
        session['unzippath'] = unzippath
        peachpit = peach_pit(
            pit_hash=hash_dirname,
            aid=app.id, pit_name=request.form.get('peach_test'),
            case_count=request.form.get('case_count')
        )
        db.session.add(peachpit)
        db.session.commit()
        pitfile2db(session['unzippath'], peach_id=peachpit.peach_id)
        db.session.commit()
        db.session.add(coverage_log_t(aid=app.id, coverage=0))
        db.session.commit()
        # 20160109修改流程获取xml之后解压，更新解压后的XML
        try:
            # 获取上一个xml中对应的值，更新到新的xml里面并上传新的hook函数--zhy
            peachpit = peach_pit.query.filter_by(aid=appid).all()
            pit_hash = []
            for peach in peachpit:
                pit_hash.append(peach.pit_hash)
            #task_hash = application_info_t.query.filter_by(id=appid).first().app_hash
            read_ftp_fuzzing_xml_path = os.path.join(taskpath, current_app.config['PIT_FOLDER'], pit_hash[-2],
                                                     'Net/ftp_fuzzing.xml')
            read_ftp_fuzzing_xmlconfig_path = os.path.join(taskpath, current_app.config['PIT_FOLDER'], pit_hash[-2],
                                                           'Net/ftp_fuzzing.xml.config')
            parameters = '{http://peachfuzzer.com/2012/Peach}Agent/{http://peachfuzzer.com/2012/Peach}Monitor/{http://peachfuzzer.com/2012/Peach}Param'
            username = read_xmldatas(read_ftp_fuzzing_xml_path, parameters, 'name', 'Username')  # 获取xml文件用户名节点
            password = read_xmldatas(read_ftp_fuzzing_xml_path, parameters, 'name', 'Password')  # 获取xml文件密码节点
            ip = read_xmldatas(read_ftp_fuzzing_xmlconfig_path, 'All/Ipv4', 'key', 'TargetIPv4')  # 获取xml文件的ip地址节点
            port = read_xmldatas(read_ftp_fuzzing_xmlconfig_path, 'All/Range', 'key', 'TargetPort')  # 获取xml文件的端口号节点

            # 更新xml中对应的值
            write_ftp_fuzzing_xml_path = os.path.join(current_app.config['NFS_FOLDER'], taskpath,
                                                      current_app.config['PIT_FOLDER'], pit_hash[-1],
                                                      'Net/ftp_fuzzing.xml')
            write_ftp_fuzzing_xmlconfig_path = os.path.join(current_app.config['NFS_FOLDER'], taskpath,
                                                            current_app.config['PIT_FOLDER'], pit_hash[-1],
                                                            'Net/ftp_fuzzing.xml.config')
            auto_update_xmldatas(write_ftp_fuzzing_xml_path, parameters, 'name', 'Username', username)  # 更新xml文件的用户名信息
            auto_update_xmldatas(write_ftp_fuzzing_xml_path, parameters, 'name', 'Password', password)  # 更新xml文件的登录密码
            auto_update_xmldatas(write_ftp_fuzzing_xmlconfig_path, 'All/Ipv4', 'key', 'TargetIPv4', ip)  # 更新xml文件的ip地址
            auto_update_xmldatas(write_ftp_fuzzing_xmlconfig_path, 'All/Range', 'key', 'TargetPort', port)  # 更新xml文件的目标端口号
            # 更新pin端/Nbitsec/nbp/function.txt文件
            hook_content_path = os.path.join(taskpath, 'hook/', hook_func)
            current_app.config['SSH_SESSION'] = ssh_connect(ip, 22, username, password)
            sftp_upload_file(current_app.config['SSH_SESSION'], hook_content_path, '/Nbitsec/nbp/function.txt')
        except Exception, e:
            # 新需求，暂时不知道会出现什么异常，所以先输出原本的异常信息以便调试
            return render_template(
                'message.html',
                message=str(e).decode('utf-8')
            )
        return redirect(url_for('main.blackfunclist', taskid=taskid))
        # 有疑问 return redirect(url_for('.opentask', taskid=taskid))

    # TODO 返回断点续测页面需要的数据   
    return render_template('features/file_config.html',
                           taskid=taskid,
                           app_port=app_port,
                           case_count=case_count,
                           peach_test=peach_test,
                           instru_mode=instru_mode,
                           app_state=app_state,
                           log_limit=log_limit,
                           ins_limit=ins_limit,
                           taint_start=taint_start,
                           taint_offset=taint_offset,
                           hook_up=hook_up
                           )


# 获得文件的唯一值ID，用于生成不重复的文件夹名
def gettaskownstr(taskhash=''):
    return taskhash + '_' + getnow()


# 传入当前任务的哈希值，返回当前任务的文件路径
def gettaskpath(hash_dirname=''):
    return os.path.realpath(
        current_app.config['NFS_FOLDER'] + hash_dirname)


# 返回特殊文件路径
def getfeaturepath_by_cookie(folder_conf=''):
    hash_dirname = request.cookies.get('task_hash')
    path = os.path.join(gettaskpath(hash_dirname), current_app.config[folder_conf])
    return path


def save_file(
        file_request, taskpath='',
        config_key='', hash_dirname=''):
    '''闯入flask文件对象保存文件并返回文件路径'''
    if not file_request or file_request.filename == '':
        return
    suffix = getSuffix(file_request.filename)
    filerealpath = os.path.join(taskpath, current_app.config[config_key]) + \
                   getfilename(hash_dirname=hash_dirname, suffix=suffix)
    file_request.save(filerealpath)
    return filerealpath


def getfilename(hash_dirname='', suffix=''):
    '''生成文件名
    >>> getfilename('filename', 'py')
    'filename.py'
    >>> getfilename('filename')
    'filename'
    '''
    if suffix is '':
        return hash_dirname
    else:
        return hash_dirname + '.' + suffix


def create_task_in_database(config_dict={}):
    '''传入用户输入的值，生成数据库数据'''
    task_info = task_info_t(
        task_name=request.cookies.get('new_task_name'),
        task_desc=request.cookies.get('new_task_info'),
        uid=getcurrentuser().id,
        task_hash=request.cookies.get('task_hash'),
        task_state=0
    )
    db.session.add(task_info)
    db.session.commit()
    print "[+] 1/6 Database Task  OK ^_^"

    stubmode = 0 if config_dict['stubmode'] == 'createmode' else 1
    app_info = application_info_t(
        tid=task_info.tid,
        app_name=request.cookies.get('app_name'),
        algorithm_mode=1,
        app_state=config_dict['app_status'],
        platform=request.cookies.get('plat_form'),
        app_hash=request.cookies.get('task_hash'),
        instru_mode=stubmode,
        app_port=config_dict['app_port'],
        iterations=0,
        time_interval=1800
    )
    db.session.add(app_info)
    db.session.commit()
    print "[+] 2/6 Database application OK ^_^"

    sampleinfo = sample_info_t(
        sample_name=current_app.config['SAMPLE_NAME_PREFIX'],
        prefix_number=1, suffix_number=1, last_number=0,
        aid=app_info.id, isexception=0,
        sample_state=6,  # this sample is not running
        taint_start=config_dict['taint_offset_start'],
        taint_offset=config_dict['taint_offset'],
        sample_hash=request.cookies.get('task_hash'),
        log_limit=config_dict['loglimit'],
        ins_limit=config_dict['ins'],
        action_index=1
    )
    db.session.add(sampleinfo)
    db.session.commit()
    print "[+] 3/6 Database sample OK ^_^"

    peachpit = peach_pit(
        pit_hash=request.cookies.get('task_hash'),
        aid=app_info.id, pit_name=config_dict['peach_test'],
        case_count=config_dict['case_count']
    )
    db.session.add(peachpit)
    db.session.commit()
    # 把peachpit的数据存入数据库
    pitfile2db(session['unzippath'], peach_id=peachpit.peach_id)
    db.session.commit()
    print "[+] 4/6 Database peachpit(test model state) OK ^_^"

    db.session.add(coverage_log_t(aid=app_info.id, coverage=0))
    db.session.commit()
    print "[+] 5/6 Database Coverage OK ^_^"

    session['taskid'] = task_info.tid
    session['appid'] = app_info.id
    session['indexTraversalTimeout'] = 1800
    session['appstate'] = app_info.app_state

    print '[+] 6/6 All Database Done, session set OK, appid is %s' % app_info.id

# 调用宋写的peachpit入库
def pitfile2db(pitdir='', peach_id=0):
    b = HandlePeachPit()
    b.initDBParam()
    b.connectDB()
    b.HandleTest("Default", peach_id)
    b.RecusWalkDir(dir=pitdir, filtrate=1)
    return True


# 生成xml文件
def create_xml(xmldict={}, xmlfilepath=''):
    '''生成xml文件'''
    from xml.etree.ElementTree import Element, SubElement, ElementTree
    config = Element('config')
    for (tagname, tagtext) in xmldict.items():
        ET = SubElement(config, tagname)
        ET.text = tagtext
    tree = ElementTree(config)
    tree.write(xmlfilepath, encoding='utf-8')


# 临时函数生成返回当前用户对象
def getcurrentuser():
    '''返回当前用户的sqlalchemy对象'''
    return User(id=1, username='001316dahihda', email='1@1.com', pass_hash='')


# 根据list生成文件夹
def create_dir_by_list(bashpath='', dirlist=[]):
    '''根据list生成文件夹
    >>> create_dir_by_list('/u/a/', ['b/', 'c/'])
    生成文件夹 '/u/a/b/', '/u/a/c/'
    '''
    os.mkdir(bashpath)
    for dirstr in dirlist:
        try:
            os.mkdir(os.path.join(bashpath, dirstr))
        except:
            return render_template(
                'message.html',
                message="创建目录失败，请检查共享目录配置。".decode('utf-8')
            )


# 获取当前文件名的后缀
def getSuffix(filename=''):
    '''获取当前文件名的后缀
    >>> getSuffix('filename.py')
    'py'
    >>> getSuffix('filename')
    ''
    '''
    try:
        suf_filename = filename.rsplit('.', 1)[1]
    except:
        suf_filename = ''
    return suf_filename


# 2016.12.1 需求修改
# 该函数用于修改xml元素中的ip地址、端口号、用户名和密码
def auto_update_xmldatas(xmlfilepath='', nodepath='', pname='', pvalue='', lastvalue=''):
    tree = read_xml(xmlfilepath)
    nodes = find_nodes(tree, nodepath)
    result_nodes = get_node_by_keyvalue(nodes, {pname: pvalue})
    change_node_properties(result_nodes, {"value": lastvalue})
    write_xml(tree, xmlfilepath)


# 2016.12.9 需求修改
# 该函数用于读取xml元素中的ip地址、端口号、用户名和密码
def read_xmldatas(xmlfilepath='', nodepath='', pname='', pvalue=''):
    tree = read_xml(xmlfilepath)
    text_nodes = get_node_by_keyvalue(find_nodes(tree, nodepath), {pname: pvalue})
    node_value = text_nodes[0].get('value')
    return node_value


def gethash(name=''):
    '''获取字符串md5
    In [84]: gethash('abc')
    Out[84]: '900150983cd24fb0d6963f7d28e17f72'
    '''
    from hashlib import md5
    return md5(name.encode('utf-8')).hexdigest()


def getnow():
    '''获取当前时间，根据config.py配置文件里FILENAME_TIMEFORMAT配置的时间格式'''
    import time
    FILENAME_TIMEFORMAT = current_app.config['FILENAME_TIMEFORMAT']
    time_str = time.strftime('%Y%m%d%H%M%S', time.localtime())
    return time_str


def gethashplus(name=''):
    '''获取哈希加时间戳'''
    return gethash(name=name) + '_' + getnow()
