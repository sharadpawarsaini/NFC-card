# Helper if you want to centralize DB logic later.
from flask_pymongo import PyMongo

def init_db(app):
    mongo = PyMongo(app)
    return mongo
