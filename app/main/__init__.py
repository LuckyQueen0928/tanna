# -*- coding: utf-8 -*-

from flask import Blueprint


main = Blueprint('main', __name__)

# 必须在末尾导入
from . import views, w_views, errors # --文档类
#from . import views, errors
