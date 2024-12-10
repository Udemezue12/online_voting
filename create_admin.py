from werkzeug.security import generate_password_hash
from online import create_app

from online.extensions import db
from online.models import User

app = create_app()

with app.app_context():
    admin_user = User(
        username="astro",
        email="admin@example.com",
        password=generate_password_hash("securepassword", method="scrypt"),
        role="chairman",
        
    )
    

    db.session.add(admin_user)
    db.session.commit()

    voter_user = User(
        username="udenkovic",
        email="voter@example.com",
        password=generate_password_hash("securepassword", method="scrypt"),
        role="voter",
        
    )
    db.session.add(voter_user)
    db.session.commit()
    print("Admin and Voter user created successfully!")
