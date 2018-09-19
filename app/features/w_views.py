# -*- coding: utf-8 -*-

import os
import datetime
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
import multiprocessing
from sqlalchemy import and_, or_
import time
from app import db
from ..models import (
    w_Globalnode,
    w_Globaledge,
    w_Partialedge,
    w_Partialnode,
    w_application_info_t, w_task_info_t, w_special_node_t, w_coverage_log_t, w_sample_info_t, w_source_asm_map,
    w_sensitive_post_t, w_constrain_info_t)
from cgi import escape
from lib.core.data import logprocesslist
from lib.core.w_processCoverageLog import w_saveCoverLog

W_NODE_COUNT_MAX = 100  # 全局函数关系图最大节点数
W_EDGE_COUNT_MAX = 200  # 全局函数关系图最大边数


# document features main page- -
@features.route('/w_features/')
def w_featmain():
    appid = session.get('w_appid')
    gnodelist = w_Globalnode.query.filter_by(aid=appid) \
        .offset(0).limit(150).all()
    return render_template(
        'features/w_funclist.html', gnodelist=gnodelist
    )


# 函数关系图页，函数信息以D3+AJAX的方式获取
@features.route('/w_node-fetter/')
def w_featfetter():
    nodeid = request.cookies.get('w_nodeid')
    return render_template(
        'features/w_featfetter.html', mainnode=nodeid
    )


# 生成函数关系json信息页面，用于生成函数关系图
# 函数关系图有如下规则：
# 1. 函数关系图为有向无环图
# 2. 程序从数据库中获取当前用户点击节点的函数关联关系，所点击的节点信息储存在cookie中
# 3. 程序获取该函数的调用关系之后，或继续获取该函数所调用或被调用函数的关联关系知道获取的节点和关联关系总数大于最大值
# 4. TODO：最大值预设于两个全局变量：W_NODE_COUNT_MAX， W_EDGE_COUNT_MAX。
@features.route('/w_fetter-json/')
def w_featfetter_json():
    appid = session.get('w_appid')
    # 获得关联函数信息集合和函数关系信息集合
    (gnodeSet, gedgeSet) = w_getfetterbynodeid()
    jsondict = {}
    # 生成d3js有向无环图所需的节点信息类json字典jsondict
    for gnode in gnodeSet:
        if gnode is None:
            break
        nyan = w_initnodedict(gnode=gnode)
        depend_edges = w_Globaledge.query.filter_by(
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
        dependedOnBy_edges = w_Globaledge.query.filter_by(
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
@features.route('/w_fetter-bbl-json/')
def w_fetter_bbl_json():
    appid = session.get('w_appid')
    nodeid = int(request.cookies.get('nodeid'), 16)
    jsondict = {}
    gnodeSet = w_Partialnode.query.filter_by(aid=appid).filter_by(parentnode=nodeid).all()
    gedgeSet = w_Partialedge.query.filter_by(aid=appid).filter_by(parentnode=nodeid).all()
    # 类似featfetter_json函数
    for gnode in gnodeSet:
        nyan = w_init_partnodedict(gnode=gnode)
        depend_edges = w_Partialedge.query.filter_by(
            aid=appid).filter_by(child=gnode.id).all()
        for depend_edge in depend_edges:
            if depend_edge in gedgeSet:
                depends_text = hex(depend_edge.parent)
                if depends_text != nyan["name"] and \
                                depends_text not in nyan["depends"]:
                    nyan["depends"].append(depends_text)
        dependedOnBy_edges = w_Partialedge.query.filter_by(
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
@features.route('/w_fetter-bbl/')
def w_fetter_bbl():
    return render_template('features/w_bbl-full-fetter.html')


'''# 获取函数的汇编及源码信息生成页面
@features.route('/w_func-src-info/<int:page>')
def w_func_src_info(page):
    # import pdb;pdb.set_trace()
    appid = session.get('w_appid')
    nodeid = int(request.cookies.get('nodeid'), 16)
    tailid = w_Globalnode.query.filter_by(id=nodeid).filter_by(aid=appid).first().tail
    asm_list = None
    if tailid == '':
        return redirect(url_for('main.w_404'))
        global asm_list
        query = w_source_asm_map.query.filter_by(aid=appid).filter(
            and_(w_source_asm_map.addr >= nodeid, w_source_asm_map.addr <= tailid)
        )
        asm_head_id = query.first().id - 1
        if asm_head_id == '':
            return redirect(url_for('main.w_404'))
        asm_end_id = query.order_by(w_source_asm_map.id.desc()).first().id
        if asm_end_id == '':
            return redirect(url_for('main.w_404'))
        asm_list = w_source_asm_map.query.filter(
            and_(w_source_asm_map.id >= asm_head_id, w_source_asm_map.id <= asm_end_id)
        ).paginate(page, per_page=50, error_out=False)
    return render_template(
        'features/w_func-src-info.html', asm_list=asm_list
    )'''


# 获取函数的汇编及源码信息生成页面
@features.route('/w_func-src-info/<int:page>')
def w_func_src_info(page):
    # import pdb;pdb.set_trace()
    appid = session.get('w_appid')
    nodeid = int(request.cookies.get('nodeid'), 16)
    tailid = w_Globalnode.query.filter_by(id=nodeid).filter_by(aid=appid).first_or_404().tail
    query = w_source_asm_map.query.filter_by(aid=appid).filter(
        and_(w_source_asm_map.addr >= nodeid, w_source_asm_map.addr <= tailid)
    )
    asm_head_id = query.first_or_404().id - 1
    asm_end_id = query.order_by(w_source_asm_map.id.desc()).first_or_404().id
    asm_list = w_source_asm_map.query.filter(
        and_(w_source_asm_map.id >= asm_head_id, w_source_asm_map.id <= asm_end_id)
    ).paginate(page, per_page=50, error_out=False)
    return render_template(
        'features/w_func-src-info.html', asm_list=asm_list
    )


@features.route('/w_ajax-func-list/<start>/<limit>/')
def w_ajax_func_list(start, limit):
    appid = session.get('w_appid')
    w_searchflag = request.args.get('w_searchflag')
    if w_searchflag is None:
        w_searchflag = ''
    glist = w_Globalnode.query.filter_by(aid=appid) \
        .filter(
            w_Globalnode.name.ilike('%{w_searchflag}%'.format(w_searchflag=w_searchflag))
            ).limit(limit).offset(start).all()
    glist_dict = {'glist': []}
    for gnode in glist:
        glist_dict['glist'].append({
            'name': gnode.name,
            'id': hex(gnode.id)
            })
    return jsonify(glist_dict)


# 根据当前点击的节点获取关系节点和关系边
def w_getfetterbynodeid():
    '''该函数会获得当前点击的节点（COOKIE值）
    并返回和这个节点关联的函数和信息
    (gnodeSet, gedgeSet)
    '''
    appid = session.get('w_appid')
    (gedgeSet, gnodeSet, gnodeidSet,
     gid_had_done, gid_not_done) = w_initlist()
    nodeid = int(request.cookies.get('nodeid'), 16)
    gnodeidSet.append(nodeid)
    gnodeSet.append(
        w_Globalnode.query.filter_by(
            aid=appid).filter_by(id=nodeid).first()
    )
    (nodenum, edgenum) = w_initmaxnum()
    # 循环获取关系和函数集合
    while True:
        gid_not_done = list(set(gnodeidSet) ^ set(gid_had_done))
        if len(gid_not_done) == 0:
            return (gnodeSet, gedgeSet)
        for gnodeid in gid_not_done:
            gedgebyparent = w_Globaledge.query.filter_by(
                aid=appid).filter_by(parent=gnodeid).all()
            for gedge in gedgebyparent:
                gnodeidSet.append(gedge.child)
                gnodeSet.append(w_Globalnode.query.filter_by(
                    aid=appid).filter_by(id=gedge.child).first()
                                )
                gedgeSet.append(gedge)
                if len(gnodeidSet) >= nodenum or \
                                len(gedgeSet) >= edgenum:
                    return (gnodeSet, gedgeSet)
            gedgebychild = w_Globaledge.query.filter_by(
                aid=appid).filter_by(child=gnodeid).all()
            for gedge in gedgebychild:
                gnodeidSet.append(gedge.parent)
                gnodeSet.append(w_Globalnode.query.filter_by(
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


# 设置与进程控制页面
@features.route('/w_process-conctrl/')
def w_process_conctrl():
    appid = session.get('w_appid')
    time_interval = w_application_info_t.query.filter_by(id=appid).first().time_interval
    pid = 0
    logpid = 0
    for process in logprocesslist:
        if process.is_alive():
            logpid = process.pid
    return render_template(
        'features/w_processConctrl.html', timeout=time_interval, pid=pid, logpid=logpid
    )


# 偏移列表
@features.route('/w_tracelist/')
def w_tracelist():
    appid = session.get('w_appid')
    app = w_application_info_t.query.filter_by(id=appid).first()
    task = w_task_info_t.query.filter_by(tid=app.tid).first()
    filelist = w_getAddrList(task, app)
    print filelist
    return render_template('features/w_tracelist.html', filelist=filelist)


# 获取当前任务的addr文件列表
def w_getAddrList(task, app):
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


# 获得当前状态，自动化遍历之后改路由待定
@features.route('/current-index/')
def w_current_index():
    appid = session.get('w_appid')
    action_index = w_sample_info_t.query.filter_by(
        sample_state=0
    ).filter_by(aid=appid).first().action_index
    return jsonify({"action_index": action_index})


# 手动修改当前要跑的状态
# 自动化遍历的情况现已舍弃该方法
@features.route('/w_change-index/', methods=['POST'])
def w_change_index():
    appid = session.get('w_appid')
    try:
        new_index = int(request.form['new_index'])
    except Exception as e:
        return jsonify({"msg": "提交失败。只能输入数字。"})
    action_index = w_sample_info_t.query.filter_by(
        sample_state=0
    ).filter_by(aid=appid).first()
    if action_index.action_index == new_index or \
                    new_index > action_index.action_count:
        return jsonify({"msg": "提交失败。不能输入当前状态且不能大于最大状态。"})
    action_index_list = w_sample_info_t.query.filter_by(
        sample_state=0
    ).filter_by(aid=appid).all()
    for action_index in action_index_list:
        action_index.sample_state = 3
    db.session.commit()
    is_index_has = w_sample_info_t.query.filter_by(
        action_index=new_index).filter_by(aid=appid).first()
    if is_index_has:
        stop_index_list = w_sample_info_t.query.filter_by(
            sample_state=3).filter_by(aid=appid). \
            filter_by(action_index=new_index).all()
        for stop_index in stop_index_list:
            stop_index.sample_state = 0
        db.session.commit()
    else:
        sample_general = w_sample_info_t.query.filter_by(
            aid=appid).first()
        new_sample = w_sample_info_t(
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


# 提交FUZZ点
@features.route('/fuzz-submit/', methods=['GET'])
def w_fuzz_submit():
    appid = session.get('w_appid')
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
    constrain_list = w_constrain_info_t.query.filter_by(aid=appid).all()
    convert_addr_list = [c.convert_addr for c in constrain_list]
    if bbl_select in convert_addr_list:
        app = w_application_info_t.query.filter_by(id=appid).first()
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


@features.route('/w_json-gettracelist/')
def w_json_gettracelist():
    # TODO, maybe Arbitrary File Read
    aid = session.get('w_appid')
    filename = request.args.get('file')
    path = w_getfeaturepath('ADDR_FOLDER')
    tracelist = open(path + filename, 'r').readlines()
    base = w_special_node_t.query.filter_by(addrtype='base').filter_by(aid=aid).first_or_404().addr
    addrlist = []
    for trace in tracelist:
        addr = hex(int(trace, 16) + base)
        addrlist.append(addr)
    return jsonify({'addrlist': addrlist})


@features.route('/w_report/w_task-<w_taskid>/', methods=['get', ''])
def w_index_report(w_taskid):
    datadict = {}
    app = w_application_info_t.query.filter_by(tid=w_taskid).first()
    w_appid = app.id
    task = w_task_info_t.query.filter_by(tid=w_taskid).first()
    has_cover = w_Partialnode.query.filter(
        or_(w_Partialnode.status == 1, w_Partialnode.status == 2)
    ).filter_by(aid=w_appid).count()
    has_found = w_Partialnode.query.filter(
        or_(w_Partialnode.status == 3, w_Partialnode.status == 4)
    ).filter_by(aid=w_appid).count()
    bbl_count = w_Partialnode.query.filter_by(aid=w_appid).count()
    # 判断执行方式（fuzz or syme ）显示对应迭代次数
    task_state = w_application_info_t.query.filter_by(tid=app.tid).first().app_state
    iterations = w_application_info_t.query.filter_by(tid=app.tid).first().iterations
    if task_state == 1 or task_state == 0:
        iterations = iterations + w_sample_info_t.query.filter_by(aid=w_appid, sample_state=2).count()
    expname_list = w_getExceptionList(task, app)
    datadict['taskname'] = task.task_name
    datadict['has_cover'] = has_cover
    datadict['bbl_count'] = bbl_count
    datadict['has_found'] = has_found
    datadict['cover_log'] = w_coverage_log_t.query.filter_by(aid=w_appid).all()
    datadict['task'] = task
    datadict['current_time'] = time.strftime(
        '%Y-%m-%d : %H-%M', time.localtime(time.time())
    )
    datadict['iterations'] = iterations
    datadict['expname_list'] = expname_list
    large_log = datadict['cover_log']
    length = len(large_log)
    timestr = w_getCoverTimetoEChart(length)
    return render_template(
        'features/w_report.html', datadict=datadict, len=len, no=0, large_log=timestr, app=app
    )

# 生成报告页面，echart.js
@features.route('/w_report/')
def w_report():
    datadict = {}
    appid = session.get('w_appid')
    app = w_application_info_t.query.filter_by(id=appid).first()
    task = w_task_info_t.query.filter_by(tid=app.tid).first()
    has_cover = w_Partialnode.query.filter(
        or_(w_Partialnode.status == 1, w_Partialnode.status == 2)
        ).filter_by(aid=appid).count()
    has_found = w_Partialnode.query.filter(
        or_(w_Partialnode.status == 3, w_Partialnode.status == 4)
        ).filter_by(aid=appid).count()
    bbl_count = w_Partialnode.query.filter_by(aid=appid).count()
    # 判断执行方式（fuzz or syme ）显示对应迭代次数
    task_state = w_application_info_t.query.filter_by(tid=app.tid).first().app_state
    # fuzz执行
    iterations = w_application_info_t.query.filter_by(tid=app.tid).first().iterations
    if task_state == 1 or task_state == 0:
        # 符号执行
        iterations = iterations + w_sample_info_t.query.filter_by(aid=appid, sample_state=2).count()
    expname_list = w_getExceptionList(task, app)
    datadict['taskname'] = task.task_name
    datadict['has_cover'] = has_cover
    datadict['bbl_count'] = bbl_count
    datadict['has_found'] = has_found
    datadict['cover_log'] = w_coverage_log_t.query.filter_by(aid=appid).all()
    datadict['task'] = task
    datadict['current_time'] = time.strftime(
        '%Y-%m-%d : %H-%M', time.localtime(time.time())
        )
    datadict['iterations'] = iterations
    datadict['expname_list'] = expname_list
    large_log = datadict['cover_log']
    length = len(large_log)
    timestr = w_getCoverTimetoEChart(length)
    return render_template(
        'features/w_report.html', datadict=datadict, len=len, no=0, large_log=timestr, app=app
        )


# 报告对比
@features.route('/w_compare/task-<num1>-<num2>')
def w_compare(num1, num2):
    info = {}
    info['task1'] = w_task_info_t.query.filter_by(tid=num1).first_or_404()
    info['task2'] = w_task_info_t.query.filter_by(tid=num2).first_or_404()
    info['app1'] = w_application_info_t.query.filter_by(tid=num1).first()
    info['app2'] = w_application_info_t.query.filter_by(tid=num2).first()
    info['has_cover1'] = w_Partialnode.query.filter(
        or_(w_Partialnode.status == 1, w_Partialnode.status == 2)
        ).filter_by(aid=info['app1'].id).count()
    info['has_found1'] = w_Partialnode.query.filter(
        or_(w_Partialnode.status == 3, w_Partialnode.status == 4)
        ).filter_by(aid=info['app1'].id).count()
    info['bbl_count1'] = w_Partialnode.query.filter_by(aid=info['app1'].id).count()
    info['has_cover2'] = w_Partialnode.query.filter(
        or_(w_Partialnode.status == 1, w_Partialnode.status == 2)
        ).filter_by(aid=info['app2'].id).count()
    info['has_found2'] = w_Partialnode.query.filter(
        or_(w_Partialnode.status == 3, w_Partialnode.status == 4)
        ).filter_by(aid=info['app2'].id).count()
    info['bbl_count2'] = w_Partialnode.query.filter_by(aid=info['app2'].id).count()
    info['cover_logs1'] = w_coverage_log_t.query.filter_by(aid=info['app1'].id).all()
    info['cover_logs2'] = w_coverage_log_t.query.filter_by(aid=info['app2'].id).all()
    large_log = info['cover_logs1'] if (
        len(info['cover_logs1']) > len(info['cover_logs2'])
    ) else info['cover_logs2']
    length = len(large_log)
    timestr = w_getCoverTimetoEChart(length)
    string1 = w_getCoverLogtoEChart(info['cover_logs1'], length)
    string2 = w_getCoverLogtoEChart(info['cover_logs2'], length)
    return render_template(
        'features/w_compare.html', info=info, string1=string1, string2=string2,
        large_log=timestr
    )


# 获取当前任务状态和算法
@features.route('/w_current_algorithm/', methods=['GET'])
def w_c_algorithm():
    appid = session.get('w_appid')
    app = w_application_info_t.query.filter_by(id=appid).first()
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
@features.route('/w_changeAlgorithm/')
def w_changeAlgorithm():
    appid = session.get('w_appid')
    alg_dict = {
        'status': 0,
        'msg': ''
    }
    app = w_application_info_t.query.filter_by(id=appid).first()
    if app.algorithm_mode == 1:
        app.algorithm_mode = 2
        alg_dict['msg'] = '符号执行算法成从深度优先转为广度优先'
    else:
        app.algorithm_mode = 1
        alg_dict['msg'] = '符号执行算法成从广度优先转为深度优先'
    db.session.commit()
    alg_dict['status'] = 1
    return jsonify(alg_dict)


def w_getCoverLogtoEChart(cover_log_list=[], length=0):
    string = ','.join([str(log.coverage) for log in cover_log_list])
    last = str(cover_log_list[-1].coverage)
    listlen = len(cover_log_list)
    if listlen < length:
        dis = length - listlen
        for _ in range(1, dis + 1):
            string = string + ',' + last
    return string


# 异常文件下载页面
# TODO：任意文件下载...
@features.route('/w_exception/name-<exceptionname>')
def w_exception(exceptionname):
    path = w_getfeaturepath('EXP_FOLDER')
    exp = '<br>'.join(open(path + exceptionname, 'r').readlines())
    response = make_response(exp)
    # response.headers["Content-Disposition"] = "attachment; filename=%s;"%'exception'
    return response


# 获取当前任务的异常文件列表
def w_getExceptionList(task, app):
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


# 开启覆盖率记录进程
@features.route('/w_start-log-process/')
def w_start_log_process():
    w_startLogProcess()
    return render_template_string(
        '<script>alert("Process has already start");window.history.go(-1);</script>'
    )


# 关闭覆盖率记录进程
@features.route('/w_stop-log-process/')
def w_stop_log_process():
    w_stopLogProcess()
    return render_template_string(
        '<script>alert("Process has already stop");window.history.go(-1);</script>'
    )


# 开启记录进程
def w_startLogProcess():
    appid = session['w_appid']
    w_stopLogProcess()
    covertimeout = 30
    p2 = multiprocessing.Process(target=w_saveCoverLog, args=(appid, covertimeout,))
    p2.start()
    logprocesslist.append(p2)


# 关闭记录进程
def w_stopLogProcess():
    if len(logprocesslist) > 0:
        for process in logprocesslist:
            process.terminate()


# ajax方式添加敏感点逼近BBL地址
@features.route('/add-Sensitive-exec/')
def w_add_Sensitive_exec():
    aye_json = {'status': 0, 'msg': ''}
    if request.cookies.get('bbl-select') is None:
        aye_json['msg'] = '未选择BBL'
        return jsonify(aye_json)
    appid = session.get('appid')
    bbl_select = request.cookies.get('bbl-select')
    pnode_tail = w_Partialnode.query.filter_by(
        id=int(bbl_select, 16)
    ).filter_by(aid=appid).first().tail
    if w_is_Sensitive_execed(aye_tail=pnode_tail, aid=appid):
        aye_json["msg"] = bbl_select + ' : ' + \
                          current_app.config['AYE_FAIL']
        return jsonify(aye_json)
    spt = w_sensitive_post_t(
        addr=pnode_tail, status=1, aid=appid
    )
    db.session.add(spt)
    db.session.commit()
    aye_json['status'] = 1
    aye_json['msg'] = bbl_select + ' : ' + \
                      current_app.config['AYE_SUCCESS']
    return jsonify(aye_json)


# 判断当前节点是否已经提交了符号执行
def w_is_Sensitive_execed(aye_tail=0, aid=0):
    spt = w_sensitive_post_t.query.filter(
        and_(w_sensitive_post_t.addr == aye_tail, w_sensitive_post_t.aid == aid)
    ).first()
    if spt is None:
        return False
    else:
        return True


# AJAX进行BBL以探测节点的动态着色
@features.route('/w_partial-node-found-tint-json/')
def w_p_tint_found_json():
    appid = session.get('w_appid')
    nodeid = request.cookies.get('nodeid')
    tint_list = w_Partialnode.query.filter_by(status=3).filter_by(aid=appid).all()
    gid_list = []
    for tintnode in tint_list:
        gid_list.append(hex(tintnode.id))
        tintnode.status = 4
    db.session.commit()
    return jsonify({"nodes": gid_list})


# AJAX进行函数已覆盖节点着色
@features.route('/w_global-node-tint-json/')
def w_g_tint_json():
    appid = session.get('w_appid')
    tint_list = w_Globalnode.query.filter_by(status=1).filter_by(aid=appid).all()
    gid_list = []
    for tintnode in tint_list:
        gid_list.append(hex(tintnode.id))
        tintnode.status = 2
    db.session.commit()
    return jsonify({"nodes": gid_list})


# AJAX进行BBL以覆盖节点的动态着色
@features.route('/w_partial-node-tint-json/')
def w_p_tint_json():
    appid = session.get('w_appid')
    nodeid = request.cookies.get('nodeid')
    tint_list = w_Partialnode.query.filter_by(status=1).filter_by(aid=appid).all()
    gid_list = []
    for tintnode in tint_list:
        gid_list.append(hex(tintnode.id))
        tintnode.status = 2
    db.session.commit()
    return jsonify({"nodes": gid_list})


# 根据当前点击的节点获取关系节点和关系边
def w_getfetterbynodeid():
    '''该函数会获得当前点击的节点（COOKIE值）
    并返回和这个节点关联的函数和信息
    (gnodeSet, gedgeSet)
    '''
    appid = session.get('w_appid')
    (gedgeSet, gnodeSet, gnodeidSet,
     gid_had_done, gid_not_done) = w_initlist()
    nodeid = int(request.cookies.get('nodeid'), 16)
    gnodeidSet.append(nodeid)
    gnodeSet.append(
        w_Globalnode.query.filter_by(
            aid=appid).filter_by(id=nodeid).first()
    )
    (nodenum, edgenum) = w_initmaxnum()
    # 循环获取关系和函数集合
    while True:
        gid_not_done = list(set(gnodeidSet) ^ set(gid_had_done))
        if len(gid_not_done) == 0:
            return (gnodeSet, gedgeSet)
        for gnodeid in gid_not_done:
            gedgebyparent = w_Globaledge.query.filter_by(
                aid=appid).filter_by(parent=gnodeid).all()
            for gedge in gedgebyparent:
                gnodeidSet.append(gedge.child)
                gnodeSet.append(w_Globalnode.query.filter_by(
                    aid=appid).filter_by(id=gedge.child).first()
                                )
                gedgeSet.append(gedge)
                if len(gnodeidSet) >= nodenum or \
                                len(gedgeSet) >= edgenum:
                    return (gnodeSet, gedgeSet)
            gedgebychild = w_Globaledge.query.filter_by(
                aid=appid).filter_by(child=gnodeid).all()
            for gedge in gedgebychild:
                gnodeidSet.append(gedge.parent)
                gnodeSet.append(w_Globalnode.query.filter_by(
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


def w_getCoverTimetoEChart(length=0):
    string = ','.join(["'" + str(datetime.timedelta(seconds=time * 30)) + "'" for time in range(length + 1)])
    return string


def w_getfeaturepath(folder_conf=''):
    taskid = session['w_taskid']
    task = w_task_info_t.query.filter_by(tid=taskid).first()
    hash_dirname = task.task_hash
    path = os.path.join(w_gettaskpath(hash_dirname), current_app.config[folder_conf])
    return path


def w_gettaskpath(hash_dirname=''):
    return os.path.realpath(
        current_app.config['NFS_FOLDER'] + hash_dirname)


# 设置Node和Link的最大值
def w_initmaxnum():
    appid = session.get('w_appid')
    nodenum = W_NODE_COUNT_MAX
    edgenum = W_EDGE_COUNT_MAX
    nodecount = w_Globalnode.query.filter_by(aid=appid).count()
    edgecount = w_Globaledge.query.filter_by(aid=appid).count()
    if nodecount < W_NODE_COUNT_MAX:
        nodenum = nodecount
    if edgecount < W_EDGE_COUNT_MAX:
        edgenum = edgecount
    return (nodenum, edgenum)


# 返回初始化节点字典
def w_initnodedict(gnode):
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
def w_init_partnodedict(gnode):
    group = ['not', 'not', 'covered', 'not', 'found']
    return {
        "docs": "",
        "type": "view",
        "name": hex(gnode.id),
        "group": group[gnode.status],
        "depends": [],
        "dependedOnBy": []
    }


# 同initnodedict
def w_initlist(gnode):
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
def w_initlist():
    gedgeSet = []
    gnodeSet = []
    gnodeidSet = []
    gid_had_done = []
    gid_not_done = []
    return (gedgeSet, gnodeSet, gnodeidSet, gid_had_done, gid_not_done)