from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from apscheduler.schedulers.background import BackgroundScheduler as Scheduler
from flask_mail import Mail
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO
from flask_admin import Admin
from online.admin import CustomAdminIndexView



db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
socketio = SocketIO()
mail = Mail()
bcrypt = Bcrypt()
cors = CORS()
scheduler = Scheduler()
csrf = CSRFProtect()
admin = Admin(name='Election Admin', template_mode='boostrap4', index_view=CustomAdminIndexView())
