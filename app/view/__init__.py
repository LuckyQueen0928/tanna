# -*- coding: utf-8 -*-

from flask import Blueprint

view = Blueprint('view', __name__)

from . import views

