import os
import logging
import hashlib
from datetime import datetime
from flask import Blueprint, render_template, url_for, redirect, flash, request
from flask_socketio import emit
from flask_login import current_user, login_required
from sqlalchemy.exc import IntegrityError
from werkzeug.utils import secure_filename
from online.extensions import db, csrf
from online.models import Election, Vote, Candidate, Category, AuditLog
from online.audit import log_error_during_vote, log_successful_vote, log_unauthorized_vote_attempt, log_vote_attempt
from online.log import loger
from online.vote.forms import CandidateForm, ElectionForm, CategoryForm


online_voting = Blueprint('online_voting', __name__)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler("app.log"),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

def update_election_status(app):
    with app.app_context():
        now = datetime.utcnow()
        elections = Election.query.all()
        for election in elections:
            election.update_status()
        db.session.commit()


@online_voting.route('/create_election', methods=['GET', 'POST'])
@login_required
def create_election():
    if current_user.role != 'chairman':
        flash('Access Denied: Only admins can create elections.', 'danger')
        return redirect(url_for('auth.index'))

    form = ElectionForm()
    if form.validate_on_submit():
        try:
            election = Election(
                title=form.title.data,
                description=form.description.data,
                start_date=form.start_date.data,
                end_date=form.end_date.data
            )
            db.session.add(election)
            db.session.commit()
            flash('Election created successfully!', 'success')
            return redirect(url_for('auth.index'))
        except Exception as e:
            db.session.rollback()
            flash(f"An error occurred while creating the election: { e}", 'danger')

    return render_template('create_election.html', form=form)


@online_voting.route('/candidates', methods=['GET', 'POST'])
@login_required
def create_candidates():
    if current_user.role != 'chairman':
        flash('Access Denied: Only admins can create candidates.', 'danger')
        return redirect(url_for('auth.index'))
    form = CandidateForm()

    form.categories.choices = [(category.id, category.name)
                               for category in Category.query.all()]
    form.election_id.choices = [(election.id, election.title)
                                for election in Election.query.all()]

    if request.method == 'POST':
        if form.validate_on_submit():
            name = form.name.data
            biography = form.biography.data
            election_id = form.election_id.data
            date_of_birth = form.date_of_birth.data
            # phone_number = form.phone_number.data
            categories_selected = form.categories.data

            # existing_candidate = Candidate.query.filter(
            #     (Candidate.phone_number == phone_number) | (
            #         Candidate.name == name)
            # ).first()

            # if existing_candidate:
            #     flash(
            #         'A candidate with this phone number or name already exists.', 'danger')
            #     return redirect(url_for('online_voting.create_candidates'))

            try:
                profile_pic_dir = 'online/static/profile_pics'
                certificates_dir = 'online/static/certificates'
                os.makedirs(profile_pic_dir, exist_ok=True)
                os.makedirs(certificates_dir, exist_ok=True)

                # Save profile picture
                profile_pic_filename = None
                if form.profile_pic.data:
                    profile_pic_file = form.profile_pic.data
                    profile_pic_filename = secure_filename(
                        profile_pic_file.filename)
                    profile_pic_path = os.path.join(
                        profile_pic_dir, profile_pic_filename)
                    profile_pic_file.save(profile_pic_path)

                # certificate_filenames = []
                # if form.certificates.data:
                #     for certificate_file in form.certificates.data[:5]:
                #         certificate_filename = secure_filename(
                #             certificate_file.filename)
                #         certificate_path = os.path.join(
                #             certificates_dir, certificate_filename)
                #         certificate_file.save(certificate_path)
                #         certificate_filenames.append(certificate_filename)

                primary_category_id = categories_selected[0]
                candidate = Candidate(
                    name=name,
                    biography=biography,
                    election_id=election_id,
                    date_of_birth=date_of_birth,
                    # phone_number=phone_number,
                    profile_pic=profile_pic_filename,
                    # certificates=",".join(certificate_filenames),
                    category_id=primary_category_id
                )

                invalid_categories = []
                for category_id in categories_selected:
                    category = Category.query.get(category_id)
                    if category:
                        candidate.categories.append(category)
                    else:
                        invalid_categories.append(category_id)

                # Commit candidate to the database
                db.session.add(candidate)
                db.session.commit()

                if invalid_categories:
                    flash(f"Invalid category IDs: {invalid_categories}. The skipped.", 'warning')

                flash('Candidate added successfully!', 'success')
                return redirect(url_for('auth.index'))

            except IntegrityError as ie:
                db.session.rollback()
                loger.log_error(f"IntegrityError occurred: {ie.orig}")
                flash('An integrity error occurred. Please check your input.', 'danger')
            except Exception as e:
                db.session.rollback()
                loger.log_error(f"Unexpected error occurred: {e}")
                flash(f'An unexpected error occurred: {e}', 'danger')

        else:
            flash(f"Form validation failed: {form.errors}", 'danger')

    return render_template('create_candidate.html', form=form)


@online_voting.route('/edit_candidate/<int:candidate_id>', methods=['GET', 'POST'])
@login_required
def edit_candidate(candidate_id):
    if current_user.role != 'chairman':
        flash('Access Denied: Only Admins can edit candidates.', 'danger')
        return redirect(url_for('auth.index'))

    candidate = Candidate.query.get_or_404(candidate_id)

    if candidate.election.start_date <= datetime.utcnow().date():
        flash('You cannot make changes to this candidate as voting has already started.', 'danger')
        return redirect(url_for('auth.index'))

    form = CandidateForm(
        name=candidate.name,
        # phone_number=candidate.phone_number,
        biography=candidate.biography,
        date_of_birth=candidate.date_of_birth,
        election_id=candidate.election_id
    )

    categories = Category.query.all()
    elections = Election.query.all()

    if not categories:
        flash('No categories available. Please add categories first.', 'warning')
        return redirect(url_for('auth.index'))

    if not elections:
        flash('No elections available. Please add elections first.', 'warning')
        return redirect(url_for('auth.index'))

    # Populate form choices
    form.categories.choices = [(category.id, category.name)
                               for category in categories]
    form.categories.data = [category.id for category in candidate.categories]
    form.election_id.choices = [(election.id, election.title)
                                for election in elections]

    if request.method == 'POST' and form.validate_on_submit():
        try:

            candidate.name = form.name.data
            candidate.phone_number = form.phone_number.data
            candidate.biography = form.biography.data
            candidate.date_of_birth = form.date_of_birth.data
            candidate.election_id = form.election_id.data

            profile_pic_dir = 'online/static/profile_pics'
            os.makedirs(profile_pic_dir, exist_ok=True)
            if form.profile_pic.data:
                profile_pic_file = form.profile_pic.data
                profile_pic_filename = secure_filename(
                    profile_pic_file.filename)
                profile_pic_path = os.path.join(
                    profile_pic_dir, profile_pic_filename)
                profile_pic_file.save(profile_pic_path)
                candidate.profile_pic = profile_pic_filename

            certificates_dir = 'online/static/certificates'
            os.makedirs(certificates_dir, exist_ok=True)
            certificate_filenames = []
            if form.certificates.data:

                for certificate_file in form.certificates.data[:5]:
                    certificate_filename = secure_filename(
                        certificate_file.filename)
                    certificate_path = os.path.join(
                        certificates_dir, certificate_filename)
                    certificate_file.save(certificate_path)
                    certificate_filenames.append(certificate_filename)

            # candidate.certificates = ",".join(certificate_filenames)

            candidate.categories = [Category.query.get(
                category_id) for category_id in form.categories.data]

            db.session.commit()
            flash('Candidate details updated successfully!', 'success')
            return redirect(url_for('auth.index'))

        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred while updating the candidate: {str(e)}', 'danger')

    return render_template('edit_candidate.html', form=form, candidate=candidate)


@online_voting.route('/candidates_by_category', methods=['GET'])
@login_required
def candidate_by_category():
    if current_user.role != 'chairman':
        flash('Access Denied: Only admins view this.', 'danger')
        return redirect(url_for('auth.index'))
    categories = Category.query.all()
    candidates_by_category = {}

    for category in categories:
        candidates = Candidate.query.filter(
            Candidate.categories.any(id=category.id)).all()
        candidates_by_category[category.name] = candidates

    return render_template('candidate_by_category.html', candidates_by_category=candidates_by_category)


@online_voting.route('/delete_candidate/<int:candidate_id>', methods=['POST'])
@login_required
@csrf.exempt
def delete_candidate(candidate_id):
    if current_user.role != 'chairman':
        flash('Access Denied', 'danger')
        return redirect(url_for('auth.index'))

    candidate = Candidate.query.get_or_404(candidate_id)

    if candidate.election.start_date <= datetime.utcnow().date():
        flash('You cannot delete this candidate as voting has started.', 'danger')
        return redirect(url_for('auth.index'))

    try:
        db.session.delete(candidate)
        db.session.commit()
        flash('Candidate deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'An error occurred while deleting the candidate: {e}', 'danger')

    return redirect(url_for('auth.index'))


@online_voting.route('/candidates/<int:category_id>')
@login_required
def candidates_by_category(category_id):
    if current_user.role != 'voter':
        flash('Access Denied: Only voters can view.', 'danger')
        return redirect(url_for('auth.index'))
    category = Category.query.get_or_404(category_id)
    candidates = Candidate.query.filter(
        Candidate.categories.contains(category)).all()
    return render_template('candidates_by_category.html', category=category, candidates=candidates)


@online_voting.route('/cast_vote/<int:candidate_id>/<int:category_id>', methods=['POST'])
@login_required
@csrf.exempt
def cast_vote(candidate_id, category_id):

    if current_user.role != 'voter':
        flash('Access Denied: Only voters are allowed to vote.', 'danger')
        log_unauthorized_vote_attempt(candidate_id)
        return redirect(url_for('auth.index'))

    candidate = Candidate.query.get_or_404(candidate_id)
    category = Category.query.get_or_404(category_id)

    election = candidate.election
    if not election or not election.status == 'ongoing':
        flash('Voting has not started.', 'danger')
        log_vote_attempt(candidate_id, "Invalid election status")
        return redirect(url_for('auth.index'))

    existing_vote = Vote.query.filter(
        Vote.user_id == current_user.id,
        Vote.category_id == category.id
    ).first()

    if existing_vote:
        flash('You have already voted in this category.', 'danger')
        log_vote_attempt(candidate_id, "Duplicate vote attempt")
        return redirect(url_for('online_voting.live_results'))

    # hashed_ip = hashlib.sha256(request.remote_addr.encode()).hexdigest()
    # existing_ip_vote = Vote.query.filter(
    #     Vote.hashed_ip == hashed_ip,
    #     Vote.category_id == category.id
    # ).first()

    # if existing_ip_vote:
    #     flash('A vote has already been cast from this device or location.', 'danger')
    #     log_vote_attempt(candidate_id, "IP-based duplicate vote attempt")
    #     return redirect(url_for('online_voting.live_results'))
    logger.info(f"User {current_user.id} attempting to vote for candidate {candidate_id} in category {category_id}")
    vote = Vote(
        user_id=current_user.id,
        candidate_id=candidate.id,
        category_id=category.id,
        # hashed_ip=hashed_ip,
        timestamp=datetime.utcnow()
    )
    

    try:
        db.session.add(vote)
        candidate.vote_count += 1
        db.session.commit()

        log_successful_vote(candidate_id)

        flash(f'Your vote for {candidate.name} in {category.name} has been recorded successfully!', 'success')

        updated_results = {c.name: c.vote_count for c in Candidate.query.all()}
        emit('update_results', updated_results,
             broadcast=True, namespace='/results')

        return redirect(url_for('online_voting.live_results'))

    except Exception as e:
        db.session.rollback()
        log_error_during_vote(candidate_id, e)
        loger.log_error(f"Unexpected error occurred: {candidate_id}, {e}")
        
        logger.info(f"IP: {request.remote_addr}, CSRF Token: {request.form.get('csrf_token')}")
        flash('An error occurred while recording your vote. Please try again.', 'danger')

    return redirect(url_for('auth.index'))


# @online_voting.route('/live_results')
# def live_results():
#     candidates = Candidate.query.all()

#     grouped_candidates = {}
#     for candidate in candidates:
#         for category in candidate.categories:
#             if category.name not in grouped_candidates:
#                 grouped_candidates[category.name] = []
#             grouped_candidates[category.name].append(candidate)

#     return render_template('live_results.html', grouped_candidates=grouped_candidates)


@online_voting.route('/live_results')
def live_results():
    candidates = Candidate.query.all()

    grouped_candidates = {}
    for candidate in candidates:
        for category in candidate.categories:
            if category.name not in grouped_candidates:
                grouped_candidates[category.name] = []
            grouped_candidates[category.name].append(candidate)

    elections = Election.query.all()
    election_started = any(
        election.start_date <= datetime.utcnow().date() < election.end_date for election in elections
    )

    return render_template(
        'live_results.html',
        grouped_candidates=grouped_candidates,
        election_started=election_started
    )


@online_voting.route('/categories')
@login_required
def categories():
    if current_user.role != 'voter':
        flash('Access Denied: Only voters view this.', 'danger')
        return redirect(url_for('auth.index'))
    categories = Category.query.all()
    return render_template('categories.html', categories=categories)


@online_voting.route('/create_category', methods=['GET', 'POST'])
@login_required
def create_category():
    if current_user.role != 'chairman':
        flash('Access Denied: Only admins can create categories.', 'danger')
        return redirect(url_for('online_voting.categories'))

    form = CategoryForm()
    if form.validate_on_submit():
        category = Category(
            name=form.name.data,
            description=form.description.data
        )
        try:
            db.session.add(category)
            db.session.commit()
            flash(f"Category '{category.name}' created successfully!", 'success')
            return redirect(url_for('online_voting.categories'))
        except Exception as e:
            db.session.rollback()
            flash(f"An error occurred while creating the category: { e}", 'danger')

    return render_template('create_category.html', form=form)


@online_voting.route('/elections', methods=['GET'])
@login_required
def elections():
    if current_user.role != 'chairman':
        flash('Access Denied: Only admins view this.', 'danger')
        return redirect(url_for('auth.index'))
    elections = Election.query.all()
    return render_template('elections.html', elections=elections)


@online_voting.route('/edit_election/<int:election_id>', methods=['GET', 'POST'])
@login_required
def edit_election(election_id):
    if current_user.role != 'chairman':
        flash('Access Denied: Only admins edit this.', 'danger')
        return redirect(url_for('auth.index'))
    election = Election.query.get_or_404(election_id)
    form = ElectionForm(obj=election)

    if form.validate_on_submit():
        election.name = form.start_date.data
        election.end_date = form.end_date.data
        election.status = form.status.data
        db.session.commit()
        flash('Election updated successfully!', 'success')
        return redirect(url_for('online_voting.elections'))

    return render_template('edit_election.html', form=form, election=election)


@online_voting.route('/delete_election/<int:election_id>', methods=['POST'])
@login_required
@csrf.exempt
def delete_election(election_id):
    if current_user.role != 'chairman':
        flash('Access Denied: Only admins delete this.', 'danger')
        return redirect(url_for('auth.index'))
    election = Election.query.get_or_404(election_id)

    try:
        db.session.delete(election)
        db.session.commit()
        flash('Election deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting election: {e}', 'danger')

    return redirect(url_for('online_voting.elections'))


@online_voting.route('/category', methods=['GET'])
@login_required
def category():
    if current_user.role != 'chairman':
        flash('Access Denied: Only admins view this.', 'danger')
        return redirect(url_for('auth.index'))
    categories = Category.query.all()
    return render_template('category.html', categories=categories)


@online_voting.route('/edit_category/<int:category_id>', methods=['GET', 'POST'])
@login_required
def edit_category(category_id):
    if current_user.role != 'chairman':
        flash('Access Denied: Only edit view this.', 'danger')
        return redirect(url_for('auth.index'))
    category = Category.query.get_or_404(category_id)
    form = CategoryForm(obj=category)

    if form.validate_on_submit():
        category.name = form.name.data
        category.description = form.description.data

        db.session.commit()
        flash('Category updated successfully!', 'success')
        return redirect(url_for('online_voting.category'))

    return render_template('edit_category.html', form=form, category=category)


@online_voting.route('/delete_category/<int:category_id>', methods=['POST'])
@login_required
@csrf.exempt
def delete_category(category_id):
    if current_user.role != 'chairman':
        flash('Access Denied: Only admins delete this.', 'danger')
        return redirect(url_for('auth.index'))
    category = Category.query.get_or_404(category_id)

    try:
        db.session.delete(category)
        db.session.commit()
        flash('Category deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting category: {e}', 'danger')

    return redirect(url_for('online_voting.category'))


@online_voting.route('/audit_logs', methods=['GET'])
@login_required
def audit_logs():
    if current_user.role != 'chairman':
        flash('Access Denied: Only admins view this.', 'danger')
        return redirect(url_for('auth.index'))
    logs = AuditLog.query.all()
    return render_template('audit_logs.html', logs=logs)
