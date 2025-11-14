import os
from dotenv import load_dotenv

load_dotenv()

MONGO_URI = os.environ.get('MONGO_URI', 'mongodb+srv://nfcure:NFC123@cluster0.nhdsx2a.mongodb.net/nfcureDB?appName=Cluster0&retryWrites=true&w=majority')
SECRET_KEY = os.environ.get('SECRET_KEY', '467894658605fghdfgdfgdfgdfgdfgdfgdfgdfg')
UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
ADMIN_KEY = os.environ.get('ADMIN_KEY', 'admin123')
