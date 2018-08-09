# -*- coding: utf-8 -*-
# !/usr/bin/env python
import os

# Reads the configuration file conf.ini and set the configuration
if os.path.exists('config_nbw.ini'):
    print('Importing environment from config_nbw.ini...')
    for line in open('config_nbw.ini'):
        var = line.strip().split('=')
        if len(var) == 2:
            os.environ[var[0]] = var[1]

from app import create_app, db
from flask.ext.script import Manager, Shell
from flask.ext.migrate import Migrate, MigrateCommand


app = create_app(os.getenv('FLASK_CONFIG') or 'default')
manager = Manager(app)
migrate = Migrate(app, db)


def make_shell_context():
    # return dict(app=app, db=db, Task=Task)
    pass
manager.add_command("shell", Shell(make_context=make_shell_context))
manager.add_command('db', MigrateCommand)


@manager.command
def test():
    """Run the unit tests."""
    import unittest
    tests = unittest.TestLoader().discover('tests')
    unittest.TextTestRunner(verbosity=2).run(tests)


if __name__ == '__main__':
    manager.run()
