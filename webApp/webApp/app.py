import _locale
import hashlib
import socket
from pathlib import Path

_locale._getdefaultlocale = (lambda *args: ['en_US', 'utf-8'])
import sys
sys.path.insert(0, "/var/www/webApp/webApp/")
import os
import zipfile
from io import BytesIO
from flask import Flask, render_template, flash, redirect, url_for, session, send_file, request, make_response,send_from_directory
from forms import LoginForm, UploadFileForm
from werkzeug.utils import secure_filename
import json
from flask_dropzone import Dropzone
from urllib.parse import quote
import unicodedata
from werkzeug.urls import url_quote
from shutil import copyfile

import servers_db
app = Flask(__name__)

dropzone = Dropzone(app)


def check_parent_exist(path):
    parent, child = path.rsplit("/", 1)
    if not Path(parent).exists():
        check_parent_exist(parent)
        Path(parent).mkdir(True, True)
        os.chmod(parent, 0o777)


@app.route('/home')
@app.route('/home?<path:folder>', methods=["GET", "POST"])
def home(folder):
    if 'username' not in session.keys():
        return redirect("login")
    upload_form = UploadFileForm()
    if request.method == "POST":
        main_folder = folder
        file = request.files.get('file')
        mimetype = file.content_type
        if mimetype == "application/x-zip-compressed":
            with zipfile.ZipFile(file, 'r') as zip_ref:
                zip_ref.extractall("/"
                                   "novbox/"+main_folder)
            for filename in zip_ref.namelist():
                s = socket.socket()
                s.connect(('212.71.250.55', 8004))
                db_path = main_folder+"/"+filename
                if filename[-1] == "/":
                    db_path = main_folder+"/"+filename[:-1]
                new_update = {"user": session['username'], "action": 1, "path": db_path, "secure_path": db_path}
                s.send(bytes(json.dumps(new_update), "utf-8"))
                servers_response = s.recv(1024).decode("utf-8")
        else:
            file.save(os.path.join("/novbox/"+main_folder, secure_filename(file.filename)))
            objects_path = file.filename

            s = socket.socket()
            s.connect(('212.71.250.55', 8004))
            secure_path = main_folder+"/"+secure_filename(objects_path)
            db_path = main_folder+"/"+objects_path
            new_update = {"user": session['username'], "action": 1, "path": db_path, "secure_path": secure_path}
            s.send(bytes(json.dumps(new_update), "utf-8"))
            servers_response = s.recv(1024).decode("utf-8")

    upload_form = UploadFileForm()

    main_folder = folder
    db = servers_db.get_connect()
    folders = list()
    servers_folders = servers_db.get_folders_names(db, main_folder)
    for fold in servers_folders:
        parent, name = fold[0].rsplit("/", 1)
        if parent == main_folder:
            folders.append(name)

    files = list()
    servers_files = servers_db.get_files_names(db, main_folder)
    for file in servers_files:
        parent, name = file[0].rsplit("/", 1)
        if parent == main_folder:
            files.append(name)

    username = session['username']
    db.close()

    return render_template('home.html', folder_path=main_folder, folders=folders, files=files, upload_form=upload_form)


@app.route('/download/<path:filename>')
def download(filename):
    try:
        #copyfile("/novbox/"+filename, secure_filename("/novbox/"+filename))
        return send_file("/novbox/"+filename, as_attachment=True)
    except Exception as e:
        print(e)


@app.route('/zipped_data/<path:folder>')
def zipped_data(folder):
    memory_file = BytesIO()
    #folder = folder.replace("$", "/")
    filename = folder + ".zip"
    with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(os.path.join("/novbox", folder)):
            for file in files:
                zipf.write(os.path.join("/novbox", folder, file))
    memory_file.seek(0)
    return send_file(memory_file,
                     attachment_filename=filename,
                     as_attachment=True)


@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if 'username' in session.keys():
        upload_form = UploadFileForm()
        username = session['username']
        return redirect(url_for('home', folder=username, upload_form=upload_form))
    s = socket.socket()
    s.connect(('212.71.250.55', 8001))
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        encoded_password = hashlib.md5(password.encode()).hexdigest()
        information = {"action": "l", "username": username, "password": encoded_password, "mac": 1}
        s.send(bytes(json.dumps(information), "utf-8"))
        response = s.recv(1024).decode("utf-8")
        if response == "ok":
            session['username'] = username
            upload_form = UploadFileForm()
            return redirect(url_for('home', folder=username, upload_form=upload_form))
        else:
            flash('ERROR: '+response, 'error')

    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    session.pop("username", None)
    return redirect('login')


if __name__ == '__main__':
    app.run(debug=True)
