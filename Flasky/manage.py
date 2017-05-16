
import os
from app import create_app
from flask_script import Manager,Shell
from flask_migrate import Migrate, MigrateCommand

app = create_app(os.getenv('Flask_CONFIG') or 'default')

