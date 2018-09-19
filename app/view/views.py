from flask import (
    render_template,
    jsonify,
    session,
    Response,
    request,
    make_response,
    redirect,
    url_for,
    current_app
)
from . import view
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
    coverage_log_t,
    peach_pit
)
from sqlalchemy import and_, or_
from app import db

@view.route('/<taskid>/')
def taskview(taskid=0):
    appid = application_info_t.query.filter_by(tid=taskid).first_or_404().id
    gnodelist = Globalnode.query.filter_by(aid=appid).all()
    return render_template(
        '/view/view_funclist.html', gnodelist=gnodelist
    )

@view.route('/view-node-fetter/')
def view_featfetter():
    nodeid = request.cookies.get('view_nodeid')
    return render_template(
        'features/view_featfetter.html', mainnode=nodeid
    )

