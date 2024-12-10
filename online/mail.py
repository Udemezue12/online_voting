import os, css_inline
from flask import current_app, render_template
from flask_mail import Message
from dotenv import load_dotenv
from online import create_app
from online.log import loger
from online.extensions import mail

app = create_app

load_dotenv()

sender = os.getenv('EMAIL_USERNAME')

def send_mail(to, template, subject, link, username, **kwargs):
    try:
        with current_app.app_context():
            msg = Message(subject=subject, sender=current_app.config['MAIL_DEFAULT_SENDER'], recipients=[to])
            html = render_template(template, username=username, link=link, **kwargs)
            inlined = css_inline.inline(html)  # Ensure this is properly tested
            msg.html = inlined
            mail.send(msg)
            current_app.logger.info(f"Email sent to {to}")
    except Exception as e:
        current_app.logger.error(f"Failed to send email: {str(e)}")
        raise
