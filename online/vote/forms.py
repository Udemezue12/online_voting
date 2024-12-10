from flask_wtf import FlaskForm
from flask_wtf.file import FileAllowed
from wtforms import StringField, TextAreaField, SubmitField, IntegerField, FileField, MultipleFileField, DateField, SelectField, SelectMultipleField,  DateTimeField as DateTimeLocalField
from wtforms.validators import InputRequired, Optional, DataRequired, Length, Regexp, ValidationError
from online.models import Category, Candidate


class ElectionForm(FlaskForm):
    title = StringField('Election Title', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])
    start_date = DateField(
        'Start Time', 
        validators=[DataRequired()], 
        format='%Y-%m-%d'
    )
    end_date = DateField(
        'End Time', 
        validators=[DataRequired()], 
        format='%Y-%m-%d'
    )
    submit = SubmitField('Create Election')


class CandidateForm(FlaskForm):
    name = StringField('Name', validators=[InputRequired()])
    biography = TextAreaField('Biography', validators=[InputRequired()])
    election_id = SelectField('Election', coerce=int, validators=[DataRequired()])
    profile_pic = FileField('Profile Picture', validators=[
        DataRequired('Upload Your Image'),
        FileAllowed(['jpeg', 'png', 'jpg', 'webp'], 'Images only!')
    ])
    # certificates = MultipleFileField('Certificates', validators=[
    #     Optional(),
    #     FileAllowed(['pdf', 'docx'], 'Only PDF or DOCX format is allowed.')
    # ])
    date_of_birth = DateField('Date of Birth', format='%Y-%m-%d', validators=[
        DataRequired(message='Please provide your date of birth.')
    ])
    # phone_number = StringField('Phone Number', validators=[
    #     DataRequired(),
    #     Length(min=10, max=20),
    #     Regexp(
    #         r'^\+?[0-9]*$', message='Phone number must contain only numbers and optionally start with a plus.'
    #     )
    # ])
    categories = SelectMultipleField(
        'Categories', coerce=int, validators=[DataRequired()]
    )
    submit = SubmitField('Add Candidate')
    
    

    def validate_phone_number(self, phone_number):
        existing_candidate = Candidate.query.filter_by(phone_number=phone_number.data).first()
        if existing_candidate:
            raise ValidationError("This phone number is already registered.")



class VoteForm(FlaskForm):
    candidate_id = SelectField('Choose Candidate', coerce=int, validators=[DataRequired()])
    category_id = SelectField('Choose Category', coerce=int, validators=[DataRequired()])
    submit = SubmitField('Vote')

    def __init__(self, *args, **kwargs):
        super(VoteForm, self).__init__(*args, **kwargs)
        # Populate categories dropdown
        self.category_id.choices = [(category.id, category.name) for category in Category.query.all()]

    def populate_candidates(self, category_id):
        category = Category.query.get(category_id)
        self.candidate_id.choices = [(candidate.id, candidate.name) for candidate in category.associated_candidates]






class CategoryForm(FlaskForm):
    name = StringField(
        'Category Name',
        validators=[
            DataRequired(),
            Length(min=2, max=250,
                   message="Name must be between 2 and 250 characters.")
        ]
    )
    description = TextAreaField('Description', validators=[Optional()])
    submit = SubmitField('Create Category')

    def validate_name(self, name):
        existing_category = Category.query.filter_by(name=name.data).first()
        if existing_category:
            raise ValidationError("This category name already exists.")
