from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash
from online.extensions import db, login_manager


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


candidate_categories = db.Table(
    'candidate_categories',
    db.Column('candidate_id', db.Integer, db.ForeignKey(
        'candidate.id'), primary_key=True),
    db.Column('category_id', db.Integer, db.ForeignKey(
        'category.id'), primary_key=True)
)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    # full_name = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(150), nullable=False)
    username = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), nullable=False, unique=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False,
                           default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False,
                           default=datetime.utcnow, onupdate=datetime.utcnow)
    # is_active = db.Column(db.Boolean, default=True, nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"User({self.username})"

    def __init__(self, email, username, role, password):
        # self.full_name = full_name
        self.email = email
        # self.role = role
        self.username = username
        self.set_password(password)
        self.role = role
        # self.is_active = True


class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
   

    def __repr__(self):
        return f"<Category(name={self.name})>"


class Candidate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    biography = db.Column(db.Text, nullable=False)
    election_id = db.Column(db.Integer, db.ForeignKey(
        'election.id'), nullable=False)
    categories = db.relationship(
        'Category', secondary=candidate_categories, backref=db.backref('associated_candidates', lazy='dynamic')
    )
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    election = db.relationship(
        'Election', backref=db.backref('candidates', lazy=True))
    profile_pic = db.Column(db.String(200), nullable=True)
    
    created_at = db.Column(db.DateTime, nullable=False,
                           default=datetime.utcnow)
    # phone_number = db.Column(db.String(20), unique=True, nullable=False)
    # certificates = db.Column(db.Text, nullable=True)
    date_of_birth = db.Column(db.Date(), nullable=False)
    vote_count = db.Column(db.Integer, default=0)

    def __repr__(self):
        return f"<Candidate(name={self.name}, vote_count={self.vote_count})>"




class Election(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.String(255), nullable=False)
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)
    status = db.Column(db.String(50), default='not_started') 

    def update_status(self):
        now = datetime.utcnow().date()
        if self.start_date <= now < self.end_date:
            self.status = 'ongoing'
        elif now >= self.end_date:
            self.status = 'ended'
        else:
            self.status = 'not_started'
        db.session.commit()

    def __repr__(self):
        return f"<Election(title={self.title}, status={self.status})>"






class Vote(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    user_id=db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    candidate_id=db.Column(db.Integer, db.ForeignKey(
        'candidate.id'), nullable=False)
    timestamp=db.Column(db.DateTime, default=datetime.utcnow)
    user=db.relationship('User', backref=db.backref('votes', lazy=True))
    candidate=db.relationship(
        'Candidate', backref=db.backref('votes', lazy=True))
    category_id=db.Column(db.Integer, db.ForeignKey(
        'category.id'), nullable=False)
    # hashed_ip = db.Column(db.String(64), nullable=False)


class AuditLog(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    action=db.Column(db.String(255), nullable=False)
    user_id=db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    candidate_id=db.Column(
        db.Integer, db.ForeignKey('candidate.id'), nullable=True)
    ip_address=db.Column(db.String(50), nullable=True)
    timestamp=db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    user=db.relationship('User', backref=db.backref('audit_logs', lazy=True))
    candidate=db.relationship(
        'Candidate', backref=db.backref('audit_logs', lazy=True))
    def __repr__(self):
        return f"<AuditLog(action={self.action}, user={self.user.username}, candidate={self.candidate.name}, ip={self.ip_address})>"



