from datetime import datetime
from flask import request
from flask_login import current_user
from online.extensions import db
from online.models import AuditLog


def log_audit(action, user, candidate, ip_address):
    """Helper function to log audit details"""
    log = AuditLog(
        action=action,
        user_id=user.id if user else None,
        candidate_id=candidate.id if candidate else None,
        ip_address=ip_address,
    )
    db.session.add(log)
    db.session.commit()


def log_unauthorized_vote_attempt(candidate_id):
    audit_log = AuditLog(
        action="Unauthorized vote attempt",
        user_id=current_user.id,
        candidate_id=candidate_id,
        ip_address=request.remote_addr,
        timestamp=datetime.utcnow()
    )
    db.session.add(audit_log)
    db.session.commit()


def log_vote_attempt(candidate_id, message):
    audit_log = AuditLog(
        action=message,
        user_id=current_user.id,
        candidate_id=candidate_id,
        ip_address=request.remote_addr,
        timestamp=datetime.utcnow()
    )
    db.session.add(audit_log)
    db.session.commit()


def log_successful_vote(candidate_id):
    audit_log = AuditLog(
        action="Successful vote",
        user_id=current_user.id,
        candidate_id=candidate_id,
        ip_address=request.remote_addr,
        timestamp=datetime.utcnow()
    )
    db.session.add(audit_log)
    db.session.commit()


def log_error_during_vote(candidate_id, error_message):
    audit_log = AuditLog(
        action=f"Error during vote: {error_message}",
        user_id=current_user.id,
        candidate_id=candidate_id,
        ip_address=request.remote_addr,
        timestamp=datetime.utcnow()
    )
    db.session.add(audit_log)
    db.session.commit()
