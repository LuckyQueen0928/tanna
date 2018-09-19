# -*- coding: utf-8 -*-

from . import db
from datetime import datetime
from sqlalchemy import DateTime


class task_info_t(db.Model):
    __tablename__ = 'task_info_t'
    tid = db.Column(db.Integer, primary_key=True)
    task_name = db.Column(db.String(100))
    task_desc = db.Column(db.String(500))
    create_date = db.Column(db.DateTime, default=datetime.now)
    uid = db.Column(db.Integer)
    task_hash = db.Column(db.String(100))
    task_state = db.Column(db.Integer)

    def __repr__(self):
        return '<task_name %r>' % self.task_name

class application_info_t(db.Model):
    __tablename__ = 'application_info_t'

    id = db.Column(db.Integer, primary_key=True)
    tid = db.Column(db.Integer, db.ForeignKey('application_info_t.tid'))
    app_name = db.Column(db.String(255))
    app_version = db.Column(db.String(255))
    app_desc = db.Column(db.String(255))
    algorithm_mode = db.Column(db.Integer)
    begin_time = db.Column(db.DateTime, default=datetime.now)
    end_time = db.Column(db.DateTime)
    app_state = db.Column(db.Integer)
    app_hash =db.Column(db.String(100))
    fuzz_addr = db.Column(db.Integer)
    platform = db.Column(db.Integer)
    instru_mode = db.Column(db.Integer)
    app_port = db.Column(db.Integer)
    iterations = db.Column(db.Integer)
    time_interval = db.Column(db.Integer)

    def __repr__(self):
        return '<app_name %r>' % self.app_name

#新增视图查询，避免联表查询速度过慢 by wcx
class indextasklist(db.Model):
    __tablename__ = 'indextasklist'

    tid = db.Column(db.Integer, primary_key=True)
    task_name = db.Column(db.String(100))
    task_desc = db.Column(db.String(500))
    create_date = db.Column(db.DateTime, default=datetime.now)
    uid = db.Column(db.Integer)
    task_state = db.Column(db.Integer)
    app_name = db.Column(db.String(255))
    app_state = db.Column(db.Integer)
    platform = db.Column(db.Integer)
    instru_mode = db.Column(db.Integer)

    def __repr__(self):
        return '<app_name %r>' % self.app_name
#新增视图查询，避免联表查询速度过慢 by wcx

class sample_info_t(db.Model):
    __tablename__ = 'sample_info_t'
    sample_id = db.Column(db.Integer, primary_key=True)
    sample_name = db.Column(db.String(100))
    prefix_number  = db.Column(db.Integer)
    suffix_number  = db.Column(db.Integer)
    last_number  = db.Column(db.Integer)
    format = db.Column(db.String(100))
    aid = db.Column(db.Integer)
    father_sample = db.Column(db.String(100))
    isexception = db.Column(db.Integer)
    sample_state = db.Column(db.Integer)
    taint_start = db.Column(db.String(100))
    taint_offset = db.Column(db.String(100))
    sample_hash = db.Column(db.String(100))
    state_id = db.Column(db.Integer)
    log_limit = db.Column(db.Integer)
    ins_limit = db.Column(db.Integer)
    action_index = db.Column(db.Integer)
    fuzz_flag=db.Column(db.Integer)
    def __repr__(self):
        return '<sample_name %r>' % self.sample_name

class Globalnode(db.Model):
    __tablename__ = 'global_node_t'
    nid = db.Column(db.Integer, primary_key=True)
    id  = db.Column(db.Integer)
    tail = db.Column(db.Integer)
    name = db.Column(db.String(128))
    status = db.Column(db.Integer)
    taskid  = db.Column(db.Integer)
    aid = db.Column(db.Integer)
    check_flag = db.Column(db.Integer)

    def __repr__(self):
        return '<name %r>' % self.name

class Globaledge(db.Model):
    __tablename__ = 'global_edge_t'
    eid = db.Column(db.Integer, primary_key=True)
    parent  = db.Column(db.Integer)
    child = db.Column(db.Integer)
    aid  = db.Column(db.Integer)
    parent_name = db.Column(db.String(256))
    child_name = db.Column(db.String(256))

    def __repr__(self):
        return '<parent_name %r>' % self.parent_name

class Partialedge(db.Model):
    __tablename__ = 'partial_edge_t'
    eid = db.Column(db.Integer, primary_key=True)
    parent  = db.Column(db.Integer)
    child = db.Column(db.Integer)
    parentnode = db.Column(db.Integer)
    aid = db.Column(db.Integer)

    def __repr__(self):
        return '<parent %r>' % self.parent

class Partialnode(db.Model):
    __tablename__ = 'partial_node_t'
    nid = db.Column(db.Integer, primary_key=True)
    id  = db.Column(db.Integer)
    tail = db.Column(db.Integer)
    parentnode = db.Column(db.Integer)
    status = db.Column(db.Integer)
    aid = db.Column(db.Integer)

    def __repr__(self):
        return '<id %r>' % self.id

class peach_pit(db.Model):
    __tablename__ = 'peach_pit'
    # is_fuzzing  = db.Column(db.Integer)
    peach_id = db.Column(db.Integer, primary_key=True)
    pit_hash = db.Column(db.String(100))
    aid = db.Column(db.Integer)
    pit_name = db.Column(db.String(100))
    case_count = db.Column(db.Integer)

    def __repr__(self):
        return '<pit_name %r>' % self.pit_name


class sensitive_addr_info(db.Model):
    __tablename__ = 'sensitive_addr_info'
    sensitive_id = db.Column(db.Integer, primary_key=True)
    aid = db.Column(db.Integer)
    sensitive_addr = db.Column(db.String(20))

    def __repr__(self):
        return '<sensitive_addr %r>' % self.sensitive_addr

class sensitive_post_t(db.Model):
    __tablename__ = 'sensitive_post_t'
    id = db.Column(db.Integer, primary_key=True)
    addr = db.Column(db.Integer)
    status = db.Column(db.Integer)
    aid = db.Column(db.Integer)

    def __repr__(self):
        return '<addr %r>' % self.addr

class source_asm_map(db.Model):
    __tablename__ = 'source_asm_map'
    id = db.Column(db.Integer, primary_key=True)
    addr = db.Column(db.Integer)
    aid = db.Column(db.Integer)
    segment = db.Column(db.String(20))
    info = db.Column(db.String(20))

    def __repr__(self):
        return '<addr %r>' % self.addr

class special_node_t(db.Model):
    __tablename__ = 'special_node_t'
    id = db.Column(db.Integer, primary_key=True)
    addr = db.Column(db.Integer)
    addrtype = db.Column(db.Integer)
    taskid = db.Column(db.Integer)
    aid = db.Column(db.Integer)

    def __repr__(self):
        return '<addr %r>' % self.addr

class trace_info_t(db.Model):
    __tablename__ = 'trace_info_t'
    trace_id = db.Column(db.Integer, primary_key=True)
    trace_name = db.Column(db.String(100))
    trace_file_addr = db.Column(db.String(100))
    prefix_number = db.Column(db.Integer)
    suffix_number = db.Column(db.Integer)
    trace_state = db.Column(db.Integer)
    convert_number = db.Column(db.Integer)
    depth = db.Column(db.Integer, default=-1)
    count = db.Column(db.Integer)
    aid = db.Column(db.Integer)
    sid = db.Column(db.Integer)
    num = db.Column(db.Integer)

    def __repr__(self):
        return '<trace_name %r>' % self.trace_name


class constrain_info_t(db.Model):
    constrain_name = db.Column(db.String(100))
    constrain_file_addr = db.Column(db.String(500))
    prefix_number = db.Column(db.Integer, default=0)
    suffix_number = db.Column(db.Integer, default=0)
    last_number = db.Column(db.Integer)
    constrain_file_state = db.Column(db.Integer)
    current_sample = db.Column(db.String(100))
    aid = db.Column(db.Integer)
    constrain_id = db.Column(db.Integer, primary_key=True)
    convert_addr = db.Column(db.Integer)

    def __repr__(self):
        return '<constrain_name %r>' % self.constrain_name


class coverage_log_t(db.Model):
    __tablename__ = 'coverage_log_t'
    id = db.Column(db.Integer, primary_key=True)
    log_time = db.Column(db.DateTime, default=datetime.now)
    coverage = db.Column(db.String)
    aid = db.Column(db.Integer)

    def __repr__(self):
        return '<id %r>' % self.id


class user_t(db.Model):
    __tablename__ = 'user_t'
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String)
    userpassword = db.Column(db.String)
    createtime = db.Column(db.DateTime, default=datetime.now)

    def __repr__(self):
        return '<username %r>' % self.username


# 文档类模型
class w_task_info_t(db.Model):
    __tablename__ = 'w_task_info_t'
    tid = db.Column(db.Integer, primary_key=True)
    task_name = db.Column(db.String(100))
    task_desc = db.Column(db.String(500))
    create_date = db.Column(db.DateTime, default=datetime.now)
    uid = db.Column(db.Integer)
    task_hash = db.Column(db.String(100))
    task_state = db.Column(db.Integer)

    def __repr__(self):
        return '<task_name %r>' % self.task_name

class w_application_info_t(db.Model):
    __tablename__ = 'w_application_info_t'

    id = db.Column(db.Integer, primary_key=True)
    tid = db.Column(db.Integer, db.ForeignKey('w_application_info_t.tid'))
    app_name = db.Column(db.String(255))
    app_version = db.Column(db.String(255))
    app_desc = db.Column(db.String(255))
    algorithm_mode = db.Column(db.Integer)
    begin_time = db.Column(db.DateTime, default=datetime.now)
    end_time = db.Column(db.DateTime)
    app_state = db.Column(db.Integer)
    app_hash =db.Column(db.String(100))
    fuzz_addr = db.Column(db.Integer)
    platform = db.Column(db.Integer)
    instru_mode = db.Column(db.Integer)
    app_port = db.Column(db.Integer)
    iterations = db.Column(db.Integer)
    time_interval = db.Column(db.Integer)

    def __repr__(self):
        return '<app_name %r>' % self.app_name

class w_indextasklist(db.Model):
    __tablename__ = 'w_indextasklist'

    tid = db.Column(db.Integer, primary_key=True)
    task_name = db.Column(db.String(100))
    task_desc = db.Column(db.String(500))
    create_date = db.Column(db.DateTime, default=datetime.now)
    uid = db.Column(db.Integer)
    task_state = db.Column(db.Integer)
    app_name = db.Column(db.String(255))
    app_state = db.Column(db.Integer)
    platform = db.Column(db.Integer)
    instru_mode = db.Column(db.Integer)

    def __repr__(self):
        return '<app_name %r>' % self.app_name

class w_sample_info_t(db.Model):
    __tablename__ = 'w_sample_info_t'
    sample_id = db.Column(db.Integer, primary_key=True)
    sample_name = db.Column(db.String(100))
    prefix_number  = db.Column(db.Integer)
    suffix_number  = db.Column(db.Integer)
    last_number  = db.Column(db.Integer)
    format = db.Column(db.String(100))
    aid = db.Column(db.Integer)
    father_sample = db.Column(db.String(100))
    isexception = db.Column(db.Integer)
    sample_state = db.Column(db.Integer)
    taint_start = db.Column(db.String(100))
    taint_offset = db.Column(db.String(100))
    sample_hash = db.Column(db.String(100))
    state_id = db.Column(db.Integer)
    log_limit = db.Column(db.Integer)
    ins_limit = db.Column(db.Integer)
    action_index = db.Column(db.Integer)
    fuzz_flag=db.Column(db.Integer)
    def __repr__(self):
        return '<sample_name %r>' % self.sample_name

class w_Globalnode(db.Model):
    __tablename__ = 'w_global_node_t'
    nid = db.Column(db.Integer, primary_key=True)
    id  = db.Column(db.Integer)
    tail = db.Column(db.Integer)
    name = db.Column(db.String(128))
    status = db.Column(db.Integer)
    taskid  = db.Column(db.Integer)
    aid = db.Column(db.Integer)
    check_flag = db.Column(db.Integer)

    def __repr__(self):
        return '<name %r>' % self.name

class w_Globaledge(db.Model):
    __tablename__ = 'w_global_edge_t'
    eid = db.Column(db.Integer, primary_key=True)
    parent  = db.Column(db.Integer)
    child = db.Column(db.Integer)
    aid  = db.Column(db.Integer)
    parent_name = db.Column(db.String(256))
    child_name = db.Column(db.String(256))

    def __repr__(self):
        return '<parent_name %r>' % self.parent_name

class w_Partialedge(db.Model):
    __tablename__ = 'w_partial_edge_t'
    eid = db.Column(db.Integer, primary_key=True)
    parent  = db.Column(db.Integer)
    child = db.Column(db.Integer)
    parentnode = db.Column(db.Integer)
    aid = db.Column(db.Integer)

    def __repr__(self):
        return '<parent %r>' % self.parent

class w_Partialnode(db.Model):
    __tablename__ = 'w_partial_node_t'
    nid = db.Column(db.Integer, primary_key=True)
    id  = db.Column(db.Integer)
    tail = db.Column(db.Integer)
    parentnode = db.Column(db.Integer)
    status = db.Column(db.Integer)
    aid = db.Column(db.Integer)

    def __repr__(self):
        return '<id %r>' % self.id

class w_peach_pit(db.Model):
    __tablename__ = 'w_peach_pit'
    # is_fuzzing  = db.Column(db.Integer)
    peach_id = db.Column(db.Integer, primary_key=True)
    pit_hash = db.Column(db.String(100))
    aid = db.Column(db.Integer)
    pit_name = db.Column(db.String(100))
    case_count = db.Column(db.Integer)

    def __repr__(self):
        return '<pit_name %r>' % self.pit_name


class w_sensitive_addr_info(db.Model):
    __tablename__ = 'w_sensitive_addr_info'
    sensitive_id = db.Column(db.Integer, primary_key=True)
    aid = db.Column(db.Integer)
    sensitive_addr = db.Column(db.String(20))

    def __repr__(self):
        return '<sensitive_addr %r>' % self.sensitive_addr

class w_sensitive_post_t(db.Model):
    __tablename__ = 'w_sensitive_post_t'
    id = db.Column(db.Integer, primary_key=True)
    addr = db.Column(db.Integer)
    status = db.Column(db.Integer)
    aid = db.Column(db.Integer)

    def __repr__(self):
        return '<addr %r>' % self.addr

class w_source_asm_map(db.Model):
    __tablename__ = 'w_source_asm_map'
    id = db.Column(db.Integer, primary_key=True)
    addr = db.Column(db.Integer)
    aid = db.Column(db.Integer)
    segment = db.Column(db.String(20))
    info = db.Column(db.String(20))

    def __repr__(self):
        return '<addr %r>' % self.addr

class w_special_node_t(db.Model):
    __tablename__ = 'w_special_node_t'
    id = db.Column(db.Integer, primary_key=True)
    addr = db.Column(db.Integer)
    addrtype = db.Column(db.Integer)
    taskid = db.Column(db.Integer)
    aid = db.Column(db.Integer)

    def __repr__(self):
        return '<addr %r>' % self.addr

class w_trace_info_t(db.Model):
    __tablename__ = 'w_trace_info_t'
    trace_id = db.Column(db.Integer, primary_key=True)
    trace_name = db.Column(db.String(100))
    trace_file_addr = db.Column(db.String(100))
    prefix_number = db.Column(db.Integer)
    suffix_number = db.Column(db.Integer)
    trace_state = db.Column(db.Integer)
    convert_number = db.Column(db.Integer)
    depth = db.Column(db.Integer, default=-1)
    count = db.Column(db.Integer)
    aid = db.Column(db.Integer)
    sid = db.Column(db.Integer)
    num = db.Column(db.Integer)

    def __repr__(self):
        return '<trace_name %r>' % self.trace_name


class w_constrain_info_t(db.Model):
    constrain_name = db.Column(db.String(100))
    constrain_file_addr = db.Column(db.String(500))
    prefix_number = db.Column(db.Integer, default=0)
    suffix_number = db.Column(db.Integer, default=0)
    last_number = db.Column(db.Integer)
    constrain_file_state = db.Column(db.Integer)
    current_sample = db.Column(db.String(100))
    aid = db.Column(db.Integer)
    constrain_id = db.Column(db.Integer, primary_key=True)
    convert_addr = db.Column(db.Integer)

    def __repr__(self):
        return '<constrain_name %r>' % self.constrain_name


class w_coverage_log_t(db.Model):
    __tablename__ = 'w_coverage_log_t'
    id = db.Column(db.Integer, primary_key=True)
    log_time = db.Column(db.DateTime, default=datetime.now)
    coverage = db.Column(db.String)
    aid = db.Column(db.Integer)

    def __repr__(self):
        return '<id %r>' % self.id


# Auth Model
class User(db.Model):
    __tablename__ = 'WEB_USER_T'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True)
    email = db.Column(db.String(64), unique=True)
    pass_hash = db.Column(db.String(128))
    # role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    user_confirm = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return '<username %r>' % self.username

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)
