from flask import Flask

UPLOAD_FOLDER = './uploads'
DOWNLOAD_FOLDER = 'static'

app = Flask(__name__, static_folder='static')
app.secret_key = "secret key"
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['DOWNLOAD_FOLDER'] = DOWNLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 1024
