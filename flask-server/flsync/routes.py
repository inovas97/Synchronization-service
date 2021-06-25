from flsync import app, mail
from flask import render_template, flash, session, redirect, send_file, request, jsonify, url_for, send_from_directory
from flsync.forms import LoginForm, UploadFileForm, ResetRequestForm, ResetPasswordForm, RegisterForm
from flask_mail import Message
from pathlib import Path
import os, socket, zipfile, hashlib, json, jwt, datetime
from io import BytesIO
from werkzeug.utils import secure_filename
import servers_db
from functools import wraps
servers_folder = "/root/servers-app"

def check_parent_exist(path):
    parent, child = path.rsplit("/", 1)
    if not Path(parent).exists():
        check_parent_exist(parent)
        Path(parent).mkdir(True, True)
        os.chmod(parent, 0o777)

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                               'favicon.ico', mimetype='image/vnd.microsoft.icon')

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
                zip_ref.extractall(servers_folder+"/"+main_folder)
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
            file.save(os.path.join(servers_folder+"/"+main_folder, secure_filename(file.filename)))
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
        return send_file(servers_folder+"/"+filename, as_attachment=True)
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
                zipf.write(os.path.join(servers_folder, folder, file))
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
            #token = jwt.encode({"user": username, "exp": datetime.datetime.utcnow()+datetime.timedelta(seconds=30)}, app.config['SECRET_KEY'])
            #return jsonify({'token ': token.decode('utf-8')})
            return redirect(url_for('home', folder=username, upload_form=upload_form))
        else:
            flash('ERROR: '+response, 'error')

    return render_template('login.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if 'username' in session.keys():
        upload_form = UploadFileForm()
        username = session['username']
        return redirect(url_for('home', folder=username, upload_form=upload_form))
    s = socket.socket()
    s.connect(('212.71.250.55', 8001))
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        email = form.email.data
        encoded_password = hashlib.md5(password.encode()).hexdigest()
        information = {"action": "r", "username": username, "password": encoded_password,"email": email, "mac": 1}
        s.send(bytes(json.dumps(information), "utf-8"))
        response = s.recv(1024).decode("utf-8")
        if response == "ok":
            session['username'] = username
            upload_form = UploadFileForm()
            #token = jwt.encode({"user": username, "exp": datetime.datetime.utcnow()+datetime.timedelta(seconds=30)}, app.config['SECRET_KEY'])
            #return jsonify({'token ': token.decode('utf-8')})
            return redirect(url_for('home', folder=username, upload_form=upload_form))
        else:
            flash('ERROR: '+response, 'error')

    return render_template('register.html', form=form)


@app.route('/logout')
def logout():
    session.pop("username", None)
    return redirect('login')

def send_reset_email(token, email):
    #try :
        msg = Message('Password Reset Request',
                    sender='tocasheri@gmail.com',
                    recipients=[email])
        msg.body = f'''To reset your password, visit the following link:
{url_for('reset_password', token=token, _external=True)}
If you did not make this request then simply ignore this email and no changes will be made.
        '''
        mail.send(msg)
        return "ok"
    #except:
    #    return False

@app.route('/reset_request',  methods=['GET', 'POST'])
def reset_request():
    form = ResetRequestForm()
    if form.validate_on_submit():
        #username = session["username"]
        username = form.username.data
        #email = "novasgiannis97@gmail.com"
        db = servers_db.get_connect()
        email = servers_db.get_email(db, username)
        db.close()
        if email is None:
            flash('This username not exists')
            return render_template('reset_request.html', form=form)
        token = jwt.encode({"user": username, "exp": datetime.datetime.utcnow()+datetime.timedelta(minutes=30)},
                             app.config['SECRET_KEY'])
        #return url_for('reset_password', token=token, _external=True)
        if send_reset_email(token, email):
            flash('An email has been sent with instructions to reset your password.', 'info')
        else:
            flash('Something wrong, Please Try again', 'info')
        return redirect('login')
    return render_template('reset_request.html', form=form)

def token_requiment(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.args.get('token')
        if not token:
            return jsonify({'message':'Token is missing'}), 403
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms="HS256")
            username = data['user']
        except:
            return jsonify({"message":"Token is expired"}), 403
        return f(username ,*args, **kwargs)
    return decorated


@app.route('/reset_password', methods =["GET", "POST"])
@token_requiment
def reset_password(username):
    form = ResetPasswordForm()
    if form.validate_on_submit():
        password = form.password.data
        confirm_password = form.confirm_password.data
        db = servers_db.get_connect()
        encoded_password = hashlib.md5(password.encode()).hexdigest()
        servers_db.update_password(db, username, encoded_password)
        db.close()
        return redirect('login')
    return render_template('reset_password.html', form=form, username=username)
    