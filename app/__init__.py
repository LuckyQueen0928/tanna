# -*- coding: utf-8 -*-

from flask import Flask, url_for
from flask.ext.sqlalchemy import SQLAlchemy
from config import config

db = SQLAlchemy()


def create_app(config_name):
    app = Flask(__name__)
    app.config.from_object(config[config_name])
    config[config_name].init_app(app)

    db.init_app(app)

    from .main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    from .auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint, url_prefix='/auth')

    from .features import features as featu_blueprint
    app.register_blueprint(featu_blueprint, url_prefix='/features')

    from .view import view as view_blueprint
    app.register_blueprint(view_blueprint, url_prefix='/view')

    app.add_template_global(hex, name='hex')
    app.add_template_global(str, name='str')

    return app
