from flask import Flask  # type: ignore
from config import Config
from flask_sqlalchemy import SQLAlchemy # type: ignore
app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)

from app import routes, models
