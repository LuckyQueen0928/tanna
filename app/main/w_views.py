# -*- coding: utf-8 -*-

import os
import shutil
import commands
from smtpd import program
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
import struct
from app.features.w_views import w_stopLogProcess, w_startLogProcess
from lib.core.processIndexd import changedbdata, changeIndex
from ..models import (
    User,
    w_indextasklist,
    w_task_info_t,
    w_application_info_t,
    w_Globaledge,
    w_sample_info_t,
    w_Globalnode,
    w_Partialnode,
    w_Partialedge,
    w_peach_pit,
    w_sensitive_addr_info,
    w_sensitive_post_t,
    w_source_asm_map,
    w_special_node_t,
    w_trace_info_t,
    w_coverage_log_t,
    w_constrain_info_t,
    task_info_t)

from app import db


# 使用utf-8编码
reload(sys)
sys.setdefaultencoding('utf-8')


# W_404页面
@main.route('/w_404')
def w_404():
    return render_template('w_404.html')


# 文档类主页兼任务列表页面
@main.route('/w_index', methods=['GET', 'POST'])
def w_index():
    page = request.args.get('page', 1, type=int)
    page = 1 if page < 1 else page
    pagination = w_indextasklist.query.order_by(
        w_indextasklist.tid.desc()).paginate(
        page, per_page=current_app.config['AW_TASKLIST_PER_PAGE'] or 10,
        error_out=False)
    count = w_indextasklist.query.count()
    tasklist = pagination
    end_page = float(count) / current_app.config['AW_TASKLIST_PER_PAGE']
    # TODO 根据请求方式，接收前段传来的move值，如果move值为1，执行查询共享目录中的多余的文件，并将其移动位置  --- by cmf
    if request.method == 'POST':
        move = request.form['move']
        if move == "1":
            # 查询并移动文件
            w_search_diff_nfs_task()
            return jsonify({'status': 1, 'msg': '文件移动成功！'})
    return render_template(
        'w_index.html', title='Home', tasklist=tasklist,
        tasknum=0, page=page, end_page=int(math.ceil(end_page)), count=count
    )


def w_search_diff_nfs_task():
    # 查找共享目录中多余的文件，并将它们移入extra文件夹中   by cmf
    task_hash1 = w_task_info_t.query.all()
    task_hash2 = task_info_t.query.all()
    task_hash = []
    for task in task_hash1:
        task_hash.append(task.task_hash)
    for task in task_hash2:
        task_hash.append(task.task_hash)
    # 取共享目录中的文件列表
    nfs_files = os.listdir(current_app.config['NFS_FOLDER'])
    # 取两个目录不一致的文件
    tmps = list(set(nfs_files).difference(set(task_hash)))
    if len(tmps) > 0:
        # 判定共享目录里面是否有extra文件夹 如果存在，删除，如果不存在就新建
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


# 文档类新建任务页面，任务名及任务描述
@main.route('/w_newtask/', methods=['GET', 'POST'])
def w_newtask():
    if request.method == 'POST':
        taskname = request.form['taskname'];print taskname
        taskinfo = request.form['taskinfo']
        if taskname == '':
            return render_template(
                'message.html', message="任务名不得为空".decode('utf-8')
            )
        resp = make_response(redirect(url_for('.w_net_upload')))
        resp.set_cookie('w_new_task_name', taskname)
        resp.set_cookie('w_new_task_info', taskinfo)
        return resp
    return render_template(
        'w_newtask.html', title='Newtask'
    )


# 文档类删除任务
@main.route('/w_deletetask/', methods=['POST'])
def w_deletetask():
    if request.method == 'POST':
        taskid = request.form['taskid']
        task = w_task_info_t.query.filter_by(tid=taskid).first()
        app = w_application_info_t.query.filter_by(tid=taskid).first()
        w_task_info_t.query.filter_by(tid=taskid).delete()
        w_application_info_t.query.filter_by(tid=taskid).delete()
        sample = w_sample_info_t.query.filter_by(aid=app.id).delete()
        gnode = w_Globalnode.query.filter_by(aid=app.id).delete()
        gedge = w_Globaledge.query.filter_by(aid=app.id).delete()
        pnode = w_Partialnode.query.filter_by(aid=app.id).delete()
        pedge = w_Partialedge.query.filter_by(aid=app.id).delete()
        peach_pit_data = w_peach_pit.query.filter_by(aid=app.id).delete()
        sensitive_addr_info_data = w_sensitive_addr_info.query.filter_by(aid=app.id).delete()
        sensitive_post_t_data = w_sensitive_post_t.query.filter_by(aid=app.id).delete()
        source_asm_map_data = w_source_asm_map.query.filter_by(aid=app.id).delete()
        special_node_t_data = w_special_node_t.query.filter_by(aid=app.id).delete()
        constrain_info_t_data = w_constrain_info_t.query.filter_by(aid=app.id).delete()
        coverage_log_t_data = w_coverage_log_t.query.filter_by(aid=app.id).delete()
        trace_info_t_data = w_trace_info_t.query.filter_by(aid=app.id).delete()
        hash_dirname = task.task_hash
        try:
            db.session.commit()
        except Exception, e:
            print str(e)
            return jsonify({'status': 0, 'msg': '任务删除失败！'})
        import shutil
        try:
            shutil.rmtree(w_gettaskpath(hash_dirname))
        except Exception, e:
            print str(e)
            pass
        return jsonify({'status': 1, 'msg': '任务删除成功！'})


# 文件上传页面
# 该页面会新建任务所需的文件夹,上传文件到对应的文件夹中，因为分布式架构的原因，文件会被上传到已经挂载的共享目录
@main.route('/w_newtask/w_net-upload', methods=['GET', 'POST'])
def w_net_upload():
    if request.method == 'POST':
        source_zip = request.files['source-zip']
        xml_file = request.files['xml']
        sample_file = request.files['sample']
        aims_main_file = request.files['process']
        app_filename = request.files['process'].filename
        # hookcontent = request.form['hook-up']
        # hooktext2file = open(u'function.txt', 'w')
        # hooktext2file.writelines((request.form['hook-up']).encode("UTF-8"))
        # hooktext2file.close()
        # hookfile = FileStorage(open(u'function.txt', 'r'), content_type='text/plain')
        if xml_file and sample_file and aims_main_file:
            # 上传四个文件
            try:
                w_hash_dirname = w_uploadfile(
                    source_zip=source_zip,
                    xml_file=xml_file,
                    sample_file=sample_file,
                    aims_main_file=aims_main_file
                    #hookfile=''
                )
                print w_hash_dirname
                # 更新数据库
                w_create_task_in_database(w_hash_dirname, app_filename)
                # 更新任务状态
                w_update_task_state(taskid=session.get('w_taskid'))
                # 判断主函数文件类型
                w_appid = session.get('w_appid')
                w_taskhash = w_application_info_t.query.filter_by(id=w_appid).first().app_hash
                w_appname = w_getfilename(w_taskhash, w_getSuffix(app_filename))
                aims_main_path = os.path.join(os.environ.get('NFS_FOLDER'), w_taskhash, current_app.config['PROCESS_FOLDER'], w_appname)
                platform = w_file_style(aims_main_path)
                if platform == 1:
                    app = w_application_info_t.query.filter_by(id=w_appid).first()
                    app.platform = 1
                    db.session.add(app)
                    db.session.commit()
                # 重命名sample文件和xml文件
                sample_path = os.path.join(os.environ.get('NFS_FOLDER'), w_taskhash, current_app.config['SAMPLE_FOLDER'])
                sid = w_sample_info_t.query.filter_by(aid=w_appid).first().sample_id
                xml_path = os.path.join(os.environ.get('NFS_FOLDER'), w_taskhash, current_app.config['XML_FOLDER'])
                sample_filepath = sample_path + '/' + 'sample.txt'
                xml_filepath = xml_path + '/' + w_taskhash+'.xml'
                sample_new_name = sample_path + '/' + w_taskhash + '-1-1-0-' + str(sid) + '-sample'
                xml_new_name = xml_path + '/' + w_taskhash + '-1-1-0-' + str(sid) + '-config.xml'
                if os.path.exists(sample_filepath):
                    os.rename(sample_filepath, sample_new_name)
                if os.path.exists(xml_filepath):
                    os.rename(xml_filepath, xml_new_name)
            except Exception as e:
                print '[!] ', str(e)
                e_info = str(e)
                return render_template(
                    'message.html',
                    message=e_info.decode('utf-8')
                )
            # resp = make_response(redirect(url_for('main.w_taskpre')))
            # resp.set_cookie('w_task_hash', w_hash_dirname)
            # resp.set_cookie('w_source_zip', source_zip.filename)
            # resp.set_cookie('w_xml_file', xml_file.filename)
            # resp.set_cookie('w_sample_file', sample_file.filename)
            # resp.set_cookie('w_process_file', aims_main_file.filename)
            # resp.set_cookie('hook_content', hookcontent)
            # resp.set_cookie('app_name', program.filename)
            # resp.set_cookie(
            # 'app_hash_name',
            # getfilename(hash_dirname, w_getSuffix(program.filename))
            # )
            #return resp
            return redirect(url_for('main.w_taskpre'))
        else:
            return render_template(
                'message.html',
                message='xml_file、sample_file and aims_main_file is not null!'
            )
    return render_template('w_net-upload.html',
                           htmltaskname=request.cookies.get('w_new_task_name'),
                           htmltaskinfo=request.cookies.get('w_new_task_info'),
                           )


# 判定文件是x86还是X86_64
def w_file_style(aims_file_path=''):
    aims_file = open(aims_file_path, 'rb')
    # 取出文件的幻数
    flag = aims_file.read(3)
    if "MZ" in flag:
        # PE文件解析
        # 设置当前文件的指针位置
        aims_file.seek(0x3c, 0)
        # 得到ntHeader的偏移
        binary_file = struct.unpack('H', aims_file.read(0x02))[0]
        # 定位到Machine的位置并取出
        aims_file.seek(binary_file+0x04, 0)
        binary_file_new = struct.unpack('H', aims_file.read(0x02))[0]
        if binary_file_new == 0x014c:
            return 0
        elif binary_file_new == 0x0200 or binary_file_new == 0x0284 or binary_file_new == 0x8664:
            return 1
        else:
            return -1
    elif "EL" in flag:
        # ELF文件解析
        # 设置当前文件的指针位置
        aims_file.seek(0x04, 0)
        ei_class = struct.unpack('B', aims_file.read(0x01))[0]
        if ei_class == 0:
            return -1
        elif ei_class == 1:
            return 0
        elif ei_class == 2:
            return 1


# ajax，用于检查任务状态，当前负责两个状态的检查
# 1. taskcreated : 任务配置之后，检查函数是否生成
# 2. pre ： 黑名单列表上传结束之后，检查预处理是否结束，并生成当前任务信息
@main.route('/w_newtask/w_check/<checktype>', methods=['get'])
def w_checking(checktype=''):
    appid = session.get('w_appid')
    msg = ''
    if checktype == 'taskcreated':
        app_state = w_application_info_t.query.filter_by(id=appid).first().app_state
        func_count = w_Globalnode.query.filter_by(aid=appid).count()
        if func_count:
            msg = u'[*] 已生成函数信息数据，总共%s条!' % str(func_count)
        else:
            msg = u'[*] 正在生成函数信息数据，如果程序包含比较多的函数，这将会等待比较长的时间！'
        return jsonify({'status': app_state, 'msg': msg})
    if checktype == 'pre':
        app_state = w_application_info_t.query.filter_by(id=appid).first().app_state
        if app_state is not 1:
            msg = u'[*] 正在处理函数信息。'
            pcount = w_Partialnode.query.filter_by(aid=appid).count()
            sam_count = w_source_asm_map.query.filter_by(aid=appid).count()
            if pcount and not sam_count:
                msg = u'[*] 已生成BBL数据，总共%s个！' % str(pcount)
            if sam_count and pcount:
                msg = u'[*] 已生成源码及汇编信息%s条！' % str(sam_count)
        return jsonify({'status': app_state, 'msg': msg})


# 开启任务的重定向页面开启当前任务并关闭其它任务，原因同上;( ´_ゝ｀)
# 该页面会将当前任务ID和当前任务所对应的程序ID写入session中
@main.route('/w_opentask/w_taskid-<w_taskid>', methods=['get'])
def w_opentask(w_taskid):
    appid = session.get('w_appid')
    if int(w_taskid) <= 0 and appid:
        w_taskid = w_application_info_t.query.filter_by(id=appid).first().tid
    app = w_application_info_t.query.filter(
        # and_(application_info_t.tid==taskid,
        # or_(application_info_t.app_state==1, application_info_t.app_state==0, application_info_t.app_state==5)
        # )
        w_application_info_t.tid == int(w_taskid)
    ).first()
    w_appid = app.id
    session['w_taskid'] = w_taskid
    session['w_appid'] = w_appid
    # update_task_state(taskid=taskid)
    # 当预处理处理没有结束的时候返回到预处理环节
    if app.app_state == 0:
        return redirect(url_for('main.w_taskpre'))
    if app.app_state == 1:
        # 开始覆盖率记录
        w_startLogProcess()
    return redirect(url_for('features.w_featmain'))


# 文件上传
def w_uploadfile(source_zip,
                 xml_file,
                 sample_file,
                 aims_main_file
                 #,hookfile
                 ):
    '''任务上传函数
    传入的五个参数都是flask的文件对象
    并返回当前任务的唯一值路径
    '''
    # 使用gettaskownstr生成匹配任务的唯一值字符串
    # 获取当前任务路径
    w_taskhash = w_gethash(request.cookies.get('w_new_task_name'))
    w_hash_dirname = w_gettaskownstr(w_taskhash)
    w_taskpath = w_gettaskpath(w_hash_dirname)
    # 根据配置文件config.py的列表，创建任务所需的文件夹
    w_create_dir_by_list(
        bashpath=w_taskpath,
        dirlist=current_app.config['AW_DIR_LIST']
    )
    # TODO：更改当前文件夹权限，临时解决其它处理端没有权限读取文件的情况
    os.system('sudo chmod 777 -R ' + w_taskpath)
    w_save_file(source_zip, w_taskpath, 'SOURCE_FOLDER', w_hash_dirname)
    # save_file(hookfile, taskpath, 'HOOK_FOLDER', hash_dirname)
    xml_file = w_save_file(xml_file, w_taskpath, 'XML_FOLDER', w_hash_dirname)
    amis_main_file = w_save_file(aims_main_file, w_taskpath, 'PROCESS_FOLDER', w_hash_dirname)
    sample_file = w_save_file(sample_file, w_taskpath, 'SAMPLE_FOLDER', 'sample')
    # unzippath = os.path.join(taskpath, current_app.config['PIT_FOLDER'])
    # unzip(pp_file, unzippath)
    # repitname(unzippath, hash_dirname)
    # session['unzippath'] = unzippath
    return w_hash_dirname


@main.route('/w_newtask/w_pre/', methods=['GET', 'POST'])
def w_taskpre():
    return render_template('w_taskpre.html')


def w_gettaskownstr(taskhash=''):
    '''获得文件的唯一值ID，用于生成不重复的文件夹名'''
    return taskhash + '_' + w_getnow()


def w_gettaskpath(hash_dirname=''):
    '''传入当前任务的哈希值，返回当前任务的文件路径'''
    return os.path.realpath(
        current_app.config['NFS_FOLDER'] + hash_dirname)


def w_getfeaturepath_by_cookie(folder_conf=''):
    '''返回特殊文件路径'''
    hash_dirname = request.cookies.get('w_task_hash')
    path = os.path.join(w_gettaskpath(hash_dirname), current_app.config[folder_conf])
    return path


def w_save_file(
        file_request, taskpath='',
        config_key='', hash_dirname=''):
    '''闯入flask文件对象保存文件并返回文件路径'''
    if not file_request or file_request.filename == '':
        return
    suffix = w_getSuffix(file_request.filename)
    filerealpath = os.path.join(taskpath, current_app.config[config_key]) + \
                   w_getfilename(hash_dirname=hash_dirname, suffix=suffix)
    file_request.save(filerealpath)
    return filerealpath


def w_getfilename(hash_dirname='', suffix=''):
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


def w_create_task_in_database(w_hash_dirname='', app_filename=''):
    # 传入用户输入的值，生成数据库数据
    task_info = w_task_info_t(
        task_name=request.cookies.get('w_new_task_name'),
        task_desc=request.cookies.get('w_new_task_info'),
        uid=w_getcurrentuser().id,
        task_hash=w_hash_dirname,
        task_state=0
    )
    db.session.add(task_info)
    db.session.commit()
    session['w_taskid'] = task_info.tid
    app_info = w_application_info_t(
        tid=task_info.tid,
        app_name=app_filename,
        algorithm_mode=1,
        app_state=0,
        platform=0,
        instru_mode=0,
        app_hash=w_hash_dirname,
        iterations=0
    )
    db.session.add(app_info)
    db.session.commit()
    session['w_appid'] = app_info.id
    sampleinfo = w_sample_info_t(
        sample_name=current_app.config['SAMPLE_NAME_PREFIX'],
        prefix_number=1,
        suffix_number=1,
        last_number=0,
        aid=app_info.id,
        isexception=0,
        sample_state=0,  # this sample is not running
        sample_hash=w_hash_dirname
    )
    db.session.add(sampleinfo)
    db.session.commit()
    sid = w_sample_info_t.sample_id
    db.session.add(w_coverage_log_t(aid=app_info.id, coverage=0))
    db.session.commit()
    return sid


# 关闭任务
@main.route('/w_task/w_shutdown/', methods=['get', 'post'])
def w_shutdownTask():
    json = {'status': 0, 'msg': ''}
    taskid = request.form['tasknum']
    # update_task_state(taskid=taskid)
    try:
        t = w_task_info_t.query.filter_by(tid=int(taskid)).first()
        t.task_state = 1
        db.session.commit()
        json['status'] = 1
        w_stopLogProcess()
        json['msg'] = '成功关闭了该任务！'
        return jsonify(json)
    except Exception, e:
        print str(e)
        json['msg'] = '关闭任务执行失败！'
        return jsonify(json)


# ;( ´_ゝ｀)
def w_update_task_state(taskid=0):
    '''开启当前任务并关闭存在与数据库中的其它任务
    任务状态（task_info_t.task_state）为0时表示该任务正在运行
    当前任务为1表示任务停止。
    该函数主要是配合某端只能跑单任务的情况;( ´_ゝ｀)
    '''
    task = w_task_info_t.query.filter_by(tid=taskid).first()
    task.task_state = 0
    othertasks = w_task_info_t.query.filter(w_task_info_t.tid != taskid).all()
    for othertask in othertasks:
        othertask.task_state = 1
    db.session.commit()


# 临时函数生成返回当前用户对象
def w_getcurrentuser():
    '''返回当前用户的sqlalchemy对象'''
    return User(id=1, username='001316dahihda', email='1@1.com', pass_hash='')


# 根据list生成文件夹
def w_create_dir_by_list(bashpath='', dirlist=[]):
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
def w_getSuffix(filename=''):
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


def w_gethash(name=''):
    '''获取字符串md5
    In [84]: gethash('abc')
    Out[84]: '900150983cd24fb0d6963f7d28e17f72'
    '''
    from hashlib import md5
    return 'w_'+md5(name.encode('utf-8')).hexdigest()


def w_getnow():
    ''''获取当前时间，根据config.py配置文件里FILENAME_TIMEFORMAT配置的时间格式'''
    import time
    FILENAME_TIMEFORMAT = current_app.config['FILENAME_TIMEFORMAT']
    time_str = time.strftime('%Y%m%d%H%M%S', time.localtime())
    return time_str


def w_get_hash_plus(name=''):
    '''获取文档类的哈希加时间戳'''
    return 'w_' + w_gethash(name=name) + '_' + w_getnow()
