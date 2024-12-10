from werkzeug.security import generate_password_hash
from online import create_app

from online.extensions import db
from online.models import User

app = create_app()

with app.app_context():
    admin_user = User(
        username="uchechukwu",
        email="udemezue0009@gmail.com",
        password=generate_password_hash("securepassword", method="scrypt"),
        role="chairman",
        
    )
    db.session.add(admin_user)
    db.session.commit()
    print("Admin user created successfully!")
