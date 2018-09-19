# -*- coding: utf-8 -*-

from flask import Blueprint

features = Blueprint('features', __name__)

from . import views, w_views # -- 文档类
# from . import views
