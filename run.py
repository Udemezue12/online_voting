from flask_migrate import Migrate
from online import create_app, db, socketio
from flask_wtf import CSRFProtect
from online.models import Category
from online.extensions import scheduler, Mail
from online.auth.routes import auth
from online.vote.routes import online_voting
from online.error_pages.handlers import error_pages
from online.vote.routes import update_election_status

# from online.chat.routes import onlineing_system

app = create_app()
Mail(app)

scheduler.add_job(func=update_election_status, args=[app], trigger="interval", minutes=1)  
scheduler.start()

# ////////
app.register_blueprint(
    auth,  template_folder='online/templates/', static_folder='online/static/')
# app.register_blueprint(core, template_folder='online/templates/', static_folder='online/static/')
# app.register_blueprint(onlineing_system, template_folder='online/templates/', static_folder='online/static/')
app.register_blueprint(error_pages, template_folder='online/templates/', static_folder='online/static/')
app.register_blueprint(online_voting, template_folder='online/templates/', static_folder='online/static/')
migrate = Migrate(app, db)


@app.context_processor
def inject_categories():
    categories = Category.query.all()
    return {'categories': categories}

if __name__ == '__main__':
   socketio.run(app, debug=True, port=3000)
