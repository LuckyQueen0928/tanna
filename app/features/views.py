# -*- coding: utf-8 -*-

from flask import (
    render_template,
    jsonify,
    session,
    Response,
    request,
    make_response,
    redirect,
    url_for,
    current_app,
    render_template_string,
    send_file,
    g
)
from . import features
from ..models import (
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
    trace_info_t,
    User,
    constrain_info_t,
    coverage_log_t
)
from sqlalchemy import and_, or_
from lib.core.processIndexd import changeIndex
from lib.core.processIndexd import getTimeCount
from lib.core.processCoverageLog import saveCoverLog
from lib.core.data import logprocesslist
from lib.core.data import indexprocesslist
from werkzeug.utils import secure_filename
from cgi import escape
import multiprocessing
from app import db
import time
import datetime
import os

NODE_COUNT_MAX = 100  # 全局函数关系图最大节点数
EDGE_COUNT_MAX = 200  # 全局函数关系图最大边数


# features main page- - 任务主界面
@features.route('/')
def featmain():
    appid = session.get('appid')
    taskid = application_info_t.query.filter_by(id=appid).first().tid
    gnodelist = Globalnode.query.filter_by(aid=appid).offset(0).limit(150).all()
    return render_template(
        'features/funclist.html', gnodelist=gnodelist, taskid=taskid
    )


# 函数关系图页，函数信息以D3+AJAX的方式获取
@features.route('/node-fetter/')
def featfetter():
    nodeid = request.cookies.get('nodeid')
    return render_template(
        'features/featfetter.html', mainnode=nodeid
    )


# 生成函数关系json信息页面，用于生成函数关系图
# 函数关系图有如下规则：
# 1. 函数关系图为有向无环图
# 2. 程序从数据库中获取当前用户点击节点的函数关联关系，所点击的节点信息储存在cookie中
# 3. 程序获取该函数的调用关系之后，或继续获取该函数所调用或被调用函数的关联关系知道获取的节点和关联关系总数大于最大值
# 4. TODO：最大值预设于两个全局变量：NODE_COUNT_MAX， EDGE_COUNT_MAX。
@features.route('/fetter-json/')
def featfetter_json():
    appid = session.get('appid')
    # 获得关联函数信息集合和函数关系信息集合
    (gnodeSet, gedgeSet) = getfetterbynodeid()
    jsondict = {}
    # 生成d3js有向无环图所需的节点信息类json字典jsondict
    for gnode in gnodeSet:
        if gnode is None:
            break
        nyan = initnodedict(gnode=gnode)
        depend_edges = Globaledge.query.filter_by(
            aid=appid).filter_by(child=gnode.id).all()
        # 生成函数的子节点信息
        for depend_edge in depend_edges:
            if depend_edge in gedgeSet:
                # 生成节点名 节点名=“函数地址：函数名”
                depends_text = hex(depend_edge.parent) + \
                               ':' + escape(depend_edge.parent_name)
                if depends_text != nyan["name"] and \
                                depends_text not in nyan["depends"]:
                    nyan["depends"].append(depends_text)
        dependedOnBy_edges = Globaledge.query.filter_by(
            aid=appid).filter_by(parent=gnode.id).all()
        # 生成函数的父节点信息
        for dependedOnBy_edge in dependedOnBy_edges:
            if dependedOnBy_edge in gedgeSet:
                dependedOnBy_text = hex(dependedOnBy_edge.child) + \
                                    ':' + escape(dependedOnBy_edge.child_name)
                if dependedOnBy_text != nyan["name"] and \
                                dependedOnBy_text not in nyan["dependedOnBy"]:
                    nyan["dependedOnBy"].append(dependedOnBy_text)
        jsondict[nyan["name"]] = nyan
    return jsonify({'data': jsondict, 'errors': []})


# 生成函数的BBL关系json数据
# 会获取当前函数的所有BBL关系信息
@features.route('/fetter-bbl-json/')
def fetter_bbl_json():
    appid = session.get('appid')
    nodeid = int(request.cookies.get('nodeid'), 16)
    jsondict = {}
    gnodeSet = Partialnode.query.filter_by(aid=appid).filter_by(parentnode=nodeid).all()
    gedgeSet = Partialedge.query.filter_by(aid=appid).filter_by(parentnode=nodeid).all()
    # 类似featfetter_json函数
    for gnode in gnodeSet:
        nyan = init_partnodedict(gnode=gnode)
        depend_edges = Partialedge.query.filter_by(
            aid=appid).filter_by(child=gnode.id).all()
        for depend_edge in depend_edges:
            if depend_edge in gedgeSet:
                depends_text = hex(depend_edge.parent)
                if depends_text != nyan["name"] and \
                                depends_text not in nyan["depends"]:
                    nyan["depends"].append(depends_text)
        dependedOnBy_edges = Partialedge.query.filter_by(
            aid=appid).filter_by(parent=gnode.id).all()
        for dependedOnBy_edge in dependedOnBy_edges:
            if dependedOnBy_edge in gedgeSet:
                dependedOnBy_text = hex(dependedOnBy_edge.child)
                if dependedOnBy_text != nyan["name"] and \
                                dependedOnBy_text not in nyan["dependedOnBy"]:
                    nyan["dependedOnBy"].append(dependedOnBy_text)
        jsondict[nyan["name"]] = nyan
    return jsonify({'data': jsondict, 'errors': []})


# 函数BBL关系页
@features.route('/fetter-bbl/')
def fetter_bbl():
    return render_template('features/bbl-full-fetter.html')


# 获取函数的汇编及源码信息生成页面
@features.route('/func-src-info/<int:page>')
def func_src_info(page):
    # import pdb;pdb.set_trace()
    appid = session.get('appid')
    nodeid = int(request.cookies.get('nodeid'), 16)
    tailid = Globalnode.query.filter_by(id=nodeid).filter_by(aid=appid).first_or_404().tail
    query = source_asm_map.query.filter_by(aid=appid) \
        .filter(
        and_(source_asm_map.addr >= nodeid, source_asm_map.addr <= tailid)
    )
    asm_head_id = query.first_or_404().id - 1
    asm_end_id = query.order_by(source_asm_map.id.desc()).first_or_404().id
    asm_list = source_asm_map.query.filter(
        and_(source_asm_map.id >= asm_head_id,
             source_asm_map.id <= asm_end_id)
    ).paginate(page, per_page=50, error_out=False)
    return render_template(
        'features/func-src-info.html', asm_list=asm_list
    )


@features.route('/ajax-func-list/<start>/<limit>/')
def ajax_func_list(start, limit):
    appid = session.get('appid')
    searchflag = request.args.get('searchflag')
    if searchflag is None:
        searchflag = ''
    glist = Globalnode.query.filter_by(aid=appid) \
        .filter(
            Globalnode.name.ilike('%{searchflag}%'.format(searchflag=searchflag))
            ).limit(limit).offset(start).all()
    glist_dict = {'glist':[]}
    for gnode in glist:
        glist_dict['glist'].append({
            'name': gnode.name,
            'id': hex(gnode.id)
        })
    return jsonify(glist_dict)


# 反转点信息列表
@features.route('/turningpoint/', methods=['GET'])
def turningpoint():
    appid = session.get('appid')
    infolist = sensitive_post_t.query.filter_by(aid=appid).all()
    print appid
    return render_template('features/turningpoint.html', infolist=infolist, num=0)


# 删除反转点信息
@features.route('/turningpoint_delete/', methods=['POST'])
def turningpoint_delete():
    if request.method == 'POST':
        addr = int(request.form['addr'])
        sensitive_post_t_data = sensitive_post_t.query.filter_by(addr=addr).delete()


# 偏移列表
@features.route('/tracelist/')
def tracelist():
    appid = session.get('appid')
    app = application_info_t.query.filter_by(id=appid).first()
    task = task_info_t.query.filter_by(tid=app.tid).first()
    filelist = getAddrList(task, app)
    print filelist
    return render_template('features/tracelist.html', filelist=filelist)


# 获取当前任务的addr文件列表
def getAddrList(task, app):
    dirname = task.task_hash
    basenfs = current_app.config['NFS_FOLDER']
    exp_folder = current_app.config['ADDR_FOLDER']
    exp_dir = os.path.join(basenfs + dirname, exp_folder)
    try:
        addr_file_list = os.listdir(exp_dir)
    except Exception, e:
        addr_file_list = []
        print '[-] ' + str(e)
    return addr_file_list


@features.route('/json-gettracelist/')
def json_gettracelist():
    # TODO, maybe Arbitrary File Read
    aid = session.get('appid')
    filename = request.args.get('file')
    path = getfeaturepath('ADDR_FOLDER')
    tracelist = open(path + filename, 'r').readlines()
    base = special_node_t.query.filter_by(addrtype='base').filter_by(aid=aid).first_or_404().addr
    addrlist = []
    for trace in tracelist:
        addr = hex(int(trace, 16) + base)
        addrlist.append(addr)
    return jsonify({'addrlist': addrlist})


@features.route('/report/task-<taskid>/', methods=['get', ''])
def report(taskid):
    app = application_info_t.query.filter_by(tid=taskid).first()
    task = task_info_t.query.filter_by(tid=taskid).first()
    appid = app.id

    has_cover = Partialnode.query.filter(
        or_(Partialnode.status == 1, Partialnode.status == 2)
        ).filter_by(aid=appid).count()
    has_found = Partialnode.query.filter(
        or_(Partialnode.status == 3, Partialnode.status == 4)
        ).filter_by(aid=appid).count()
    bbl_count = Partialnode.query.filter_by(aid=appid).count()

    # 自动判断任务模式显示对应迭代次数   --- by cmf
    iterations = app.iterations
    if iterations is None:
        iterations = 0
    else:
        iterations = iterations + sample_info_t.query.filter_by(aid=appid, sample_state=2).count()
    expname_list = getExceptionList(task, app)
    datadict = {'taskname': task.task_name,
                'has_cover': has_cover,
                'bbl_count': bbl_count,
                'has_found': has_found,
                'cover_log': coverage_log_t.query.filter_by(aid=appid).all(),
                'task': task,
                'current_time': time.strftime('%Y-%m-%d : %H-%M', time.localtime(time.time())),
                'iterations': iterations,
                'expname_list': expname_list
                }
    length = len(datadict['cover_log'])
    timestr = getCoverTimetoEChart(length)
    return render_template('features/report.html',
                           datadict=datadict, len=length, no=0, large_log=timestr, app=app)


'''
# 生成报告页面，echart.js
@features.route('/report/')
def report():
    datadict = {}
    appid = session.get('appid')
    app = application_info_t.query.filter_by(id=appid).first()
    task = task_info_t.query.filter_by(tid=app.tid).first()
    has_cover = Partialnode.query.filter(
        or_(Partialnode.status == 1, Partialnode.status == 2)
        ).filter_by(aid=appid).count()
    has_found = Partialnode.query.filter(
        or_(Partialnode.status == 3, Partialnode.status == 4)
        ).filter_by(aid=appid).count()
    bbl_count = Partialnode.query.filter_by(aid=appid).count()
    # TODO 自动判断任务模式显示对应迭代次数   --- by cmf
    task_mode = application_info_t.query.filter_by(tid=app.tid).first().app_state
    #fuzz 执行
    iterations = application_info_t.query.filter_by(tid=app.tid).first().iterations
    if iterations == None:
        iterations = 0
    if task_mode == 1 or task_mode == 0:
    #符号执行
        iterations = iterations + sample_info_t.query.filter_by(aid=appid, sample_state=2).count()

    expname_list = getExceptionList(task, app)
    datadict['taskname'] = task.task_name
    datadict['has_cover'] = has_cover
    datadict['bbl_count'] = bbl_count
    datadict['has_found'] = has_found
    datadict['cover_log'] = coverage_log_t.query.filter_by(aid=appid).all()
    datadict['task'] = task
    datadict['current_time'] = time.strftime(
        '%Y-%m-%d : %H-%M', time.localtime(time.time())
        )
    datadict['iterations'] = iterations
    datadict['expname_list'] = expname_list
    large_log = datadict['cover_log']
    length = len(large_log)
    timestr = getCoverTimetoEChart(length)
    return render_template(
        'features/report.html', datadict=datadict, len=len, no=0, large_log=timestr,app=app
        )
'''

# 报告对比
@features.route('/compare/task-<num1>-<num2>')
def compare(num1, num2):
    info = {}
    info['task1'] = task_info_t.query.filter_by(tid=num1).first_or_404()
    info['task2'] = task_info_t.query.filter_by(tid=num2).first_or_404()
    info['app1'] = application_info_t.query.filter_by(tid=num1).first()
    info['app2'] = application_info_t.query.filter_by(tid=num2).first()
    info['has_cover1'] = Partialnode.query.filter(
        or_(Partialnode.status == 1, Partialnode.status == 2)
        ).filter_by(aid=info['app1'].id).count()
    info['has_found1'] = Partialnode.query.filter(
        or_(Partialnode.status == 3, Partialnode.status == 4)
        ).filter_by(aid=info['app1'].id).count()
    info['bbl_count1'] = Partialnode.query.filter_by(aid=info['app1'].id).count()
    info['has_cover2'] = Partialnode.query.filter(
        or_(Partialnode.status == 1, Partialnode.status == 2)
        ).filter_by(aid=info['app2'].id).count()
    info['has_found2'] = Partialnode.query.filter(
        or_(Partialnode.status == 3, Partialnode.status == 4)
        ).filter_by(aid=info['app2'].id).count()
    info['bbl_count2'] = Partialnode.query.filter_by(aid=info['app2'].id).count()
    info['cover_logs1'] = coverage_log_t.query.filter_by(aid=info['app1'].id).all()
    info['cover_logs2'] = coverage_log_t.query.filter_by(aid=info['app2'].id).all()
    large_log = info['cover_logs1'] if (
        len(info['cover_logs1']) > len(info['cover_logs2'])
    ) else info['cover_logs2']
    length = len(large_log)
    timestr = getCoverTimetoEChart(length)
    string1 = getCoverLogtoEChart(info['cover_logs1'], length)
    string2 = getCoverLogtoEChart(info['cover_logs2'], length)
    return render_template(
        'features/compare.html', info=info, string1=string1, string2=string2,
        large_log=timestr
    )


def getCoverLogtoEChart(cover_log_list=[], length=0):
    string = ','.join([str(log.coverage) for log in cover_log_list])
    last = str(cover_log_list[-1].coverage)
    listlen = len(cover_log_list)
    if listlen < length:
        dis = length - listlen
        for _ in range(1, dis + 1):
            string = string + ',' + last
    return string


def getCoverTimetoEChart(length=0):
    string = ','.join(["'" + str(datetime.timedelta(seconds=time * 30)) + "'" for time in range(length + 1)])
    return string


# 异常文件下载页面
# TODO：任意文件下载...
@features.route('/exception/name-<exceptionname>')
def exception(exceptionname):
    path = getfeaturepath('EXP_FOLDER')
    exp = '<br>'.join(open(path + exceptionname, 'r').readlines())
    response = make_response(exp)
    # response.headers["Content-Disposition"] = "attachment; filename=%s;"%'exception'
    return response


@features.route('/json-bbl-coverage/')
def jsonCoverage():
    option = {
        'title ': {
            'text': '当前BBL覆盖率 ： 50%',
            'subtext': 'time',
            'x': 'center'
        },
        'tooltip ': {
            'trigger': 'item',
            'formatter': "/{b/} : /{c/} (/{d/}%)"
        },
        'legend': {
            'orient': 'vertical',
            'left': 'left',
            'data': ['已覆盖BBL数', '未覆盖BBL数']
        },
        'series ': [
            {
                'name': '覆盖率',
                'type': 'pie',
                'radius ': '55%',
                'center': ['50%', '60%'],
                'data': [
                    {'value': 11, 'name': '已覆盖BBL数'},
                    {'value': 20, 'name': '未覆盖BBL数'}
                ],
                'itemStyle': {
                    'emphasis': {
                        'shadowBlur': 10,
                        'shadowOffsetX': 0,
                        'shadowColor': 'rgba(0, 0, 0, 0.9)'
                    }
                }
            }
        ]
    }
    return jsonify(option)


def gettaskpath(hash_dirname=''):
    return os.path.realpath(
        current_app.config['NFS_FOLDER'] + hash_dirname)


def getfeaturepath(folder_conf=''):
    taskid = session['taskid']
    task = task_info_t.query.filter_by(tid=taskid).first()
    hash_dirname = task.task_hash
    path = os.path.join(gettaskpath(hash_dirname), current_app.config[folder_conf])
    return path


# 获取当前任务的异常文件列表
def getExceptionList(task, app):
    dirname = task.task_hash
    basenfs = current_app.config['NFS_FOLDER']
    exp_folder = current_app.config['EXP_FOLDER']
    exp_dir = os.path.join(basenfs + dirname, exp_folder)
    try:
        expname_list = os.listdir(exp_dir)
    except Exception, e:
        expname_list = []
        print '[-] ' + str(e)
    return expname_list


# ajax方式添加敏感点逼近BBL地址
@features.route('/add-Sensitive-exec/')
def add_Sensitive_exec():
    aye_json = {'status': 0, 'msg': ''}
    if request.cookies.get('bbl-select') is None:
        aye_json['msg'] = '未选择BBL'
        return jsonify(aye_json)
    appid = session.get('appid')
    bbl_select = request.cookies.get('bbl-select')
    pnode_tail = Partialnode.query.filter_by(
        id=int(bbl_select, 16)
    ).filter_by(aid=appid).first().tail
    if is_Sensitive_execed(aye_tail=pnode_tail, aid=appid):
        aye_json["msg"] = bbl_select + ' : ' + \
                          current_app.config['AYE_FAIL']
        return jsonify(aye_json)
    spt = sensitive_post_t(
        addr=pnode_tail, status=1, aid=appid
    )
    db.session.add(spt)
    db.session.commit()
    aye_json['status'] = 1
    aye_json['msg'] = bbl_select + ' : ' + \
                      current_app.config['AYE_SUCCESS']
    return jsonify(aye_json)


# AJAX进行BBL以探测节点的动态着色
@features.route('/partial-node-found-tint-json/')
def p_tint_found_json():
    appid = session.get('appid')
    nodeid = request.cookies.get('nodeid')
    tint_list = Partialnode.query.filter_by(status=3).filter_by(aid=appid).all()
    gid_list = []
    for tintnode in tint_list:
        gid_list.append(hex(tintnode.id))
        tintnode.status = 4
    db.session.commit()
    return jsonify({"nodes": gid_list})


# AJAX进行函数已覆盖节点着色
@features.route('/global-node-tint-json/')
def g_tint_json():
    appid = session.get('appid')
    tint_list = Globalnode.query.filter_by(status=1).filter_by(aid=appid).all()
    gid_list = []
    for tintnode in tint_list:
        gid_list.append(hex(tintnode.id))
        tintnode.status = 2
    db.session.commit()
    return jsonify({"nodes": gid_list})


# AJAX进行BBL以覆盖节点的动态着色
@features.route('/partial-node-tint-json/')
def p_tint_json():
    appid = session.get('appid')
    nodeid = request.cookies.get('nodeid')
    tint_list = Partialnode.query.filter_by(status=1).filter_by(aid=appid).all()
    gid_list = []
    for tintnode in tint_list:
        gid_list.append(hex(tintnode.id))
        tintnode.status = 2
    db.session.commit()
    return jsonify({"nodes": gid_list})


# 手动修改当前要跑的状态
# 自动化遍历的情况现已舍弃该方法
@features.route('/change-index/', methods=['POST'])
def change_index():
    appid = session.get('appid')
    try:
        new_index = int(request.form['new_index'])
    except Exception as e:
        return jsonify({"msg": "提交失败。只能输入数字。"})
    action_index = sample_info_t.query.filter_by(
        sample_state=0
    ).filter_by(aid=appid).first()
    if action_index.action_index == new_index or \
                    new_index > action_index.action_count:
        return jsonify({"msg": "提交失败。不能输入当前状态且不能大于最大状态。"})
    action_index_list = sample_info_t.query.filter_by(
        sample_state=0
    ).filter_by(aid=appid).all()
    for action_index in action_index_list:
        action_index.sample_state = 3
    db.session.commit()
    is_index_has = sample_info_t.query.filter_by(
        action_index=new_index).filter_by(aid=appid).first()
    if is_index_has:
        stop_index_list = sample_info_t.query.filter_by(
            sample_state=3).filter_by(aid=appid). \
            filter_by(action_index=new_index).all()
        for stop_index in stop_index_list:
            stop_index.sample_state = 0
        db.session.commit()
    else:
        sample_general = sample_info_t.query.filter_by(
            aid=appid).first()
        new_sample = sample_info_t(
            sample_name=sample_general.sample_name,
            prefix_number=1, suffix_number=1, last_number=0,
            aid=sample_general.aid,
            isexception=sample_general.isexception,
            sample_state=0,
            taint_start=sample_general.taint_start,
            taint_offset=sample_general.taint_offset,
            sample_hash=sample_general.sample_hash,
            action_index=new_index,
            action_count=sample_general.action_count,
        )
        db.session.add(new_sample)
        db.session.commit()
    return jsonify({
        "action_index": new_index,
        "msg": "提交成功，从状态" + str(action_index.action_index) + \
               "转换到状态" + str(new_index)
        })


# 更改当前的状态从符号执行到FUZZ
@features.route('/to-symbolic/', methods=['GET'])
def tosymbolic():
    appid = session.get('appid')
    app = application_info_t.query.filter_by(id=appid).first()
    if app.algorithm_mode == 4:
        app.algorithm_mode = 1
        app.fuzz_addr = 0
        db.session.commit()
        return jsonify({
            'status': 1,
            'msg': '状态已经从fuzz更改到符号执行'
        })
    else:
        return jsonify({
            'status': 0,
            'msg': '当前状态无法更改到符号执行'
        })


# 只跑FUZZ
@features.route('/only-fuzzing/', methods=['GET'])
def onlyFuzzing():
    appid = session.get('appid')
    msg_dict = {'status': 0, 'msg': ''}
    app = application_info_t.query.filter_by(id=appid).first()
    if app.app_state == 5:
        app.app_state = 1
        msg_dict['status'] = 1
        msg_dict['msg'] = '更改任务状态成功，当前状态就是状态1'
    elif app.app_state == 1:
        app.app_state = 5
        msg_dict['status'] = 1
        msg_dict['msg'] = '更改任务状态成功，当前状态就是状态5'
    else:
        msg_dict['msg'] = '更改任务状态失败'
    db.session.commit()
    return jsonify(msg_dict)


# 提交FUZZ点
@features.route('/fuzz-submit/', methods=['GET'])
def fuzz_submit():
    appid = session.get('appid')
    if request.cookies.get('bbl-select') is None:
        return jsonify({
            'status': 0,
            'msg': '未选择BBL'
        })
    bbl_select = int(request.cookies.get('bbl-select'), 16)
    # sample_list = sample_info_t.query.filter_by(aid=appid).all()
    # sidlist = [sample.sample_id for sample in sample_list]
    # constrain_list = constrain_info_t.query.filter(
    #     constrain_info_t.sid.in_((sidlist))).all()
    constrain_list = constrain_info_t.query.filter_by(aid=appid).all()
    convert_addr_list = [c.convert_addr for c in constrain_list]
    if bbl_select in convert_addr_list:
        app = application_info_t.query.filter_by(id=appid).first()
        app.fuzz_addr = bbl_select
        app.algorithm_mode = 4
        return jsonify({
            'status': 1,
            'msg': '提交成功，更改当前状态到fuzz'
        })
    else:
        return jsonify({
            'status': 0,
            'msg': '提交失败，该地址未进行敏感点逼近'
        })


# 获取当前任务状态和算法
@features.route('/current_algorithm/', methods=['GET'])
def c_algorithm():
    appid = session.get('appid')
    app = application_info_t.query.filter_by(id=appid).first()
    alg_dict = {
        'status': 1,
        'msg': '当前状态无法确定。'
    }
    if app.app_state == 1:
        if app.algorithm_mode == 0:
            alg_dict['status'] = 0
            alg_dict['msg'] = '当前任务还未开始运行。'
        if app.algorithm_mode == 1:
            alg_dict['msg'] = '当前状态为符号执行。当前算法为深度优先。'
        if app.algorithm_mode == 2:
            alg_dict['msg'] = '当前状态为符号执行。当前算法为广度优先。'
        if app.algorithm_mode == 3:
            alg_dict['msg'] = '当前状态为敏感点逼近。'
        if app.algorithm_mode == 4:
            alg_dict['msg'] = '当前状态为FUZZING。'
    elif app.app_state == 5:
        alg_dict['msg'] == '当前状态为FUZZ_ONLY!'
    return jsonify(alg_dict)


# 深度优先和广度优先的算法转换
@features.route('/changeAlgorithm/')
def changeAlgorithm():
    appid = session.get('appid')
    alg_dict = {
        'status': 0,
        'msg': ''
    }
    app = application_info_t.query.filter_by(id=appid).first()
    if app.algorithm_mode == 1:
        app.algorithm_mode = 2
        alg_dict['msg'] = '符号执行算法成从深度优先转为广度优先'
    else:
        app.algorithm_mode = 1
        alg_dict['msg'] = '符号执行算法成从广度优先转为深度优先'
    db.session.commit()
    alg_dict['status'] = 1
    return jsonify(alg_dict)


# 获得当前状态，自动化遍历之后改路由待定
@features.route('/current-index/')
def current_index():
    appid = session.get('appid')
    action_index = sample_info_t.query.filter_by(
        sample_state=0
    ).filter_by(aid=appid).first().action_index
    return jsonify({"action_index": action_index})


# 设置与进程控制页面
@features.route('/process-conctrl/')
def process_conctrl():
    appid = session.get('appid')
    time_interval = application_info_t.query.filter_by(id=appid).first().time_interval
    pid = 0
    logpid = 0
    for process in indexprocesslist:
        if process.is_alive():
            pid = process.pid
    for process in logprocesslist:
        if process.is_alive():
            logpid = process.pid
    return render_template(
        'features/processConctrl.html', timeout=time_interval, pid=pid, logpid=logpid
    )


# 设置状态遍历总时间
@features.route('/setTotalTime/', methods=['POST'])
def setTotalTime():
    appid = session.get('appid')
    if not request.form['timeout']:
        return render_template_string(
            '<script>alert("Input can not be Null!");window.history.go(-1);</script>'
        )
    totalTime = int(request.form['timeout'])
    timeCount = getTimeCount(appid=appid)
    timeout = totalTime / timeCount
    app_info = application_info_t.query.filter_by(id=appid).first()
    app_info.time_interval = timeout
    db.session.add(app_info)
    db.session.commit()
    session['indexTraversalTimeout'] = timeout
    startIndexTraversalProcess(timeout=timeout, whoneed=1)
    return render_template_string(
        '<script>alert("The total number of states is ' + str(
            timeCount) + ',  Process has already restart");window.history.go(-1);</script>'
    )


# 按钮～关闭遍历进程
@features.route('/stop-index-process/')
def stop_index_process():
    stopIndexTraversalProcess()
    return render_template_string(
        '<script>alert("Process has already stop");window.history.go(-1);</script>'
    )


# 按钮～开启遍历进程
@features.route('/start-index-process/')
def start_index_process():
    startIndexTraversalProcess(timeout=0, whoneed=2)
    return render_template_string(
        '<script>alert("Process has already start");window.history.go(-1);</script>'
    )


# 按钮～切换下一个状态（whoneed=3 切换下一个状态）
@features.route('/next_index_process/')
def next_index_process():
    startIndexTraversalProcess(timeout=0, whoneed=3)
    return render_template_string(
        '<script>alert("Switch to next action");window.history.go(-1);</script>'
    )


# 开启覆盖率记录进程
@features.route('/start-log-process/')
def start_log_process():
    startLogProcess()
    return render_template_string(
        '<script>alert("Process has already start");window.history.go(-1);</script>'
    )


# 关闭覆盖率记录进程
@features.route('/stop-log-process/')
def stop_log_process():
    stopLogProcess()
    return render_template_string(
        '<script>alert("Process has already stop");window.history.go(-1);</script>'
    )


# 修改当前自动化遍历的周期
@features.route('/changeIndexTraversalTimeout/', methods=['POST'])
def changeIndexTraversalTimeout():
    timeout = int(request.form['timeout'])
    appid = session.get('appid')
    app_info = application_info_t.query.filter_by(id=appid).first()
    app_info.time_interval = timeout
    db.session.add(app_info)
    db.session.commit()
    if not timeout:
        return render_template_string(
            '<script>alert("Input can not be Null!");window.history.go(-1);</script>'
        )
    session['indexTraversalTimeout'] = timeout
    startIndexTraversalProcess(timeout=timeout, whoneed=1)
    return render_template_string(
        '<script>alert("Process has already restart");window.history.go(-1);</script>'
    )


# 判断当前节点是否已经提交了符号执行
def is_Sensitive_execed(aye_tail=0, aid=0):
    spt = sensitive_post_t.query.filter(
        and_(sensitive_post_t.addr == aye_tail, sensitive_post_t.aid == aid)
    ).first()
    if spt is None:
        return False
    else:
        return True


# 返回初始化节点字典
def initnodedict(gnode):
    group = ['', 'done', 'error', 'done']
    return {
        "docs": "",  # 当前节点文档，暂时不用
        "type": "view",  # 当前节点类型，暂时没啥用
        "name": hex(gnode.id) + ':' + escape(gnode.name),  # 节点名，会显示再节点中
        "group": group[gnode.status],  # 节点状态
        "depends": [],  # 函数依赖的点地址
        "dependedOnBy": []  # 节点被依赖的点地址
    }


# 同initnodedict
def init_partnodedict(gnode):
    group = ['not', 'not', 'covered', 'not', 'found']
    return {
        "docs": "",
        "type": "view",
        "name": hex(gnode.id),
        "group": group[gnode.status],
        "depends": [],
        "dependedOnBy": []
    }


# 初始化获取函数关系图所需要的列表项
def initlist():
    gedgeSet = []
    gnodeSet = []
    gnodeidSet = []
    gid_had_done = []
    gid_not_done = []
    return (gedgeSet, gnodeSet, gnodeidSet, gid_had_done, gid_not_done)


# 根据当前点击的节点获取关系节点和关系边
def getfetterbynodeid():
    '''该函数会获得当前点击的节点（COOKIE值）
    并返回和这个节点关联的函数和信息
    (gnodeSet, gedgeSet)
    '''
    appid = session.get('appid')
    (gedgeSet, gnodeSet, gnodeidSet,
     gid_had_done, gid_not_done) = initlist()
    nodeid = int(request.cookies.get('nodeid'), 16)
    gnodeidSet.append(nodeid)
    gnodeSet.append(
        Globalnode.query.filter_by(
            aid=appid).filter_by(id=nodeid).first()
    )
    (nodenum, edgenum) = initmaxnum()
    # 循环获取关系和函数集合
    while True:
        gid_not_done = list(set(gnodeidSet) ^ set(gid_had_done))
        if len(gid_not_done) == 0:
            return (gnodeSet, gedgeSet)
        for gnodeid in gid_not_done:
            gedgebyparent = Globaledge.query.filter_by(
                aid=appid).filter_by(parent=gnodeid).all()
            for gedge in gedgebyparent:
                gnodeidSet.append(gedge.child)
                gnodeSet.append(Globalnode.query.filter_by(
                    aid=appid).filter_by(id=gedge.child).first()
                                )
                gedgeSet.append(gedge)
                if len(gnodeidSet) >= nodenum or \
                                len(gedgeSet) >= edgenum:
                    return (gnodeSet, gedgeSet)
            gedgebychild = Globaledge.query.filter_by(
                aid=appid).filter_by(child=gnodeid).all()
            for gedge in gedgebychild:
                gnodeidSet.append(gedge.parent)
                gnodeSet.append(Globalnode.query.filter_by(
                    aid=appid).filter_by(id=gedge.parent).first()
                                )
                gedgeSet.append(gedge)
                if len(gnodeidSet) >= nodenum or \
                                len(gedgeSet) >= edgenum:
                    return (gnodeSet, gedgeSet)
            gid_had_done.append(gnodeid)
            if len(gnodeidSet) >= nodenum or \
                            len(gedgeSet) >= edgenum:
                return (gnodeSet, gedgeSet)


# 设置Node和Link的最大值
def initmaxnum():
    appid = session.get('appid')
    nodenum = NODE_COUNT_MAX
    edgenum = EDGE_COUNT_MAX
    nodecount = Globalnode.query.filter_by(aid=appid).count()
    edgecount = Globaledge.query.filter_by(aid=appid).count()
    if nodecount < NODE_COUNT_MAX:
        nodenum = nodecount
    if edgecount < EDGE_COUNT_MAX:
        edgenum = edgecount
    return (nodenum, edgenum)


# 开启自动化遍历及记录进程
def startProcess(timeout=0, whoneed=0):
    startIndexTraversalProcess(timeout=timeout, whoneed=whoneed)
    startLogProcess()
    return True


# 开启自动化状态遍历函数
def startIndexTraversalProcess(timeout=0, whoneed=0):
    ''' whoneed参数
        1|更改遍历时间 |更改总遍历时间 |关闭遍历进程后，再重启（不停 不发）
        2|创建任务（可停） |断点续测 |开启遍历进程按钮        （要停 要发）
        3|手动切换下一个状态                                 （要停 要发 且action_index+1）
        4|超时后自动切换状态                                 （要停 要发 且action_index自动切换+1）
        5|Web服务端重启                                     （不停 要发）(不停 不发)
        '''
    try:
        currentTaskid = task_info_t.query.filter_by(task_state=0).first().tid
    except Exception, e:
        print ('No task running')
        return
    appid = application_info_t.query.filter_by(tid=currentTaskid).first().id
    session['appid'] = appid
    time_interval = application_info_t.query.filter_by(id=appid).first().time_interval
    s_timeout = session.get('indexTraversalTimeout')
    if not timeout and not s_timeout:
        timeout = int(time_interval)
    elif not timeout and s_timeout:
        timeout = int(s_timeout)
    elif timeout:
        timeout = timeout
    # import pdb;pdb.set_trace()
    session['indexTraversalTimeout'] = timeout
    stopIndexTraversalProcess()
    p = multiprocessing.Process(target=changeIndex, args=(appid, timeout, whoneed))
    p.start()
    print "[+] Start index traversal process OK"
    indexprocesslist.append(p)


# 关闭自动化便利进程
def stopIndexTraversalProcess():
    if len(indexprocesslist) > 0:
        for process in indexprocesslist:
            process.terminate()


# 开启记录进程
def startLogProcess():
    try:
        currentTaskid = task_info_t.query.filter_by(task_state=0).first().tid
    except Exception, e:
        print ('No task running')
        return
    appid = application_info_t.query.filter_by(tid=currentTaskid).first().id
    stopLogProcess()
    covertimeout = 30
    p2 = multiprocessing.Process(target=saveCoverLog, args=(appid, covertimeout,))
    p2.start()
    logprocesslist.append(p2)
    print ('[+] Start Coverlog process OK')


# 关闭记录进程
def stopLogProcess():
    if len(logprocesslist) > 0:
        for process in logprocesslist:
            process.terminate()


def prediction(path='', aid=0):
    return
    nodenum = 0
    base = special_node_t.query.filter_by(addrtype='base').filter_by(aid=aid).first().addr
    filelist = os.listdir(path)
    addrset = set()
    for file in filelist:
        filerealpath = path + file
        f = open(filerealpath, 'r')
        for line in f.readlines():
            addrset.add(line.strip())
    for addr in addrset:
        nodeaddr = base + int(addr.strip(), 16)
        p = Partialnode.query.filter(and_(
            Partialnode.id >= nodeaddr, Partialnode.tail <= nodeaddr
        )).filter_by(aid=aid).first()
        if p:
            nodenum = nodenum + 1
    return nodenum


def getpath(task=None, dira=''):
    dirname = task.task_hash
    basenfs = current_app.config['NFS_FOLDER']
    exp_folder = dira
    exp_dir = os.path.join(basenfs + dirname, exp_folder)
    return exp_dir
