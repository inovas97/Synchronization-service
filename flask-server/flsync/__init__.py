from flask import Flask
from flask_mail import Mail
from flsync.config import Config
from flask_dropzone import Dropzone

mail = Mail()
app = Flask(__name__)
app.config.from_object(Config)
mail.init_app(app)
dropzone = Dropzone(app)

from flsync import routes