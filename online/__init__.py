from flask import Flask
from werkzeug.security import generate_password_hash
from config import Config
from online.socketio import ResultsNamespace
from online.extensions import db, migrate, login_manager, socketio, csrf, mail, cors, admin
from online.models import User, Election, Candidate
from online.admin import AdminOnlyModelView


def create_app():

    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    migrate.init_app(app)
    login_manager.init_app(app)
    socketio.init_app(app)
    csrf.init_app(app)
    # mail.init_app(app)
    cors.init_app(app)
    admin.init_app(app)



    with app.app_context():
        from online.models import User, Candidate, Election, Vote
        
       
        # print("Admin user created successfully!")
        # admin.add_view(AdminOnlyModelView(User, db.session))
        # admin.add_view(AdminOnlyModelView(Election, db.session))
        # admin.add_view(AdminOnlyModelView(Candidate, db.session))

    return app


socketio.on_namespace(ResultsNamespace('/results'))

login_manager.login_view = 'auth.login'
login_manager.refresh_view = 'auth.login'
login_manager.needs_refresh_message = 'You need to Login Again'
