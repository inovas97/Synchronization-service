import json, os ,platform, queue, shutil, socket,hashlib, threading, time, sys
from pathlib import Path
from threading import Thread
from uuid import getnode as get_mac
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent
import clients_db
from tkinter import *
from tkinter import font as tkfont
global_frames = {}


def linux_path(path):
    return path.replace("\\", "/")


def devices_slash():
    if platform.system() == "Windows":
        return "\\"
    return "/"


def devices_path(db_path):
    if platform.system() == "Windows":
        return db_path.replace("/", "\\")
    return db_path


def delete_destroyed_files():
    destroyed_files = clients_db.select_destroyed_files()
    for file in destroyed_files:
        dev_path = devices_path(file[0])
        if Path(dev_path).exists():
            os.remove(dev_path)
        clients_db.delete_object(file[0])


def receive_data(object_path, filesize, receive_socket, change_timestamp):
    received_bytes = 0
    fd = open(object_path, "rb+")
    while filesize > received_bytes:
        to_write = receive_socket.recv(1024)
        print(to_write)
        fd.seek(received_bytes, 0)
        wrote = fd.write(to_write)
        receive_socket.send(bytes("ok", "utf-8"))
        received_bytes += len(to_write)
    fd.truncate(filesize)
    fd.close()
    created_timestamp = os.stat(object_path).st_atime
    os.utime(object_path, (created_timestamp, change_timestamp))


def create_conflict(src):
    dest = src + ".conf"
    sfd = open(src, "rb")
    dfd = open(dest, "wb")
    to_write = sfd.read(1024)
    while len(to_write) == 1024:
        dfd.write(to_write)
        to_write = sfd.read(1024)
    sfd.close()
    dfd.write(to_write)
    dfd.close()


def check_parents_exists(path):
    parent, child = path.rsplit("/", 1)
    dev_parent_path = devices_path(parent)
    if not Path(dev_parent_path).exists():
        check_parents_exists(parent)
        if clients_db.select_object(parent) is None:
            clients_db.insert_object(parent, 1, 1)
        Path(dev_parent_path).mkdir(True, True)


def receive_updates():
    global username
    global mac
    global users_pass
    message = StringVar()
    global home_frame
    message = {}
    mess = {}
    message_label = {}
    counter = 0
    s = socket.socket()
    sockets.append(s)
    s.connect(('212.71.250.55', 8002))
    information = {"users_pass": users_pass, "username": username, "mac": mac}
    s.send(bytes(json.dumps(information), "utf-8"))
    print("receiver send ", information)
    while 1:
        try:
            new_message = s.recv(1024).decode("utf-8")
            new_update = json.loads(new_message)
            counter+=1
            
            message[counter] = StringVar()
            message_label[counter] = Label(home_frame, textvariable=message[counter],bg="black",fg="green", font=("calibri", 11))
            message_label[counter].pack()
    
            print("receive ", new_update)
            if new_update["action"] == 1:
                path = new_update["path"]
                mess[counter] = "i received created : "+new_update["path"]
                message[counter].set(mess[counter])
                os_path = devices_path(path)
                if Path(os_path).exists() and ((Path(os_path).is_dir()) or
                                               (clients_db.select_object(path) is not None and clients_db.get_latest_update(
                                                   path) == new_update["latest_update"])):
                    mess[counter] += " ignore!"
                    message[counter].set(mess[counter])
                    message_label[counter].after(5000, message_label[counter].destroy)
                    
                    print("ignore message")
                    s.send(bytes("completed", "utf-8"))
                    continue

                check_parents_exists(path)
                if Path(os_path).exists() and clients_db.select_object(path) is not None and os.path.getmtime(
                        os_path) != clients_db.get_latest_update(path):
                    mess[counter] += " conflict!"
                    message[counter].set(mess[counter])
                    message_label[counter].after(5000, message_label[counter].destroy)
                    
                    print("conflict")
                    create_conflict(os_path)
                if new_update["type"] == 1:
                    clients_db.insert_object(path, -1, 1)
                    Path(os_path).mkdir(True, True)
                    clients_db.update_object(path, new_update["latest_update"], 0)
                else:
                    if Path(os_path).exists():
                        clients_db.update_object(path, -1, 1)
                    else:
                        if clients_db.select_object(path) is None:
                            clients_db.insert_object(path, -1, 1)
                        else:
                            clients_db.update_object(path, -1, 1)
                    open(os_path, "w")
                    if new_update["size"] > 0:
                        s.send(bytes("send bytes", "utf-8"))
                        receive_data(devices_path(new_update["path"]), new_update["size"], s, new_update["latest_update"])
                    created_timestamp = os.stat(os_path).st_atime
                    os.utime(os_path, (created_timestamp, new_update["latest_update"]))
                    clients_db.update_object(path, new_update["latest_update"], 0)
            elif new_update["action"] == 2:
                path = new_update["path"]
                mess[counter] = "i received modified : "+new_update["path"]
                message[counter].set(mess[counter])
                os_path = devices_path(path)
                check_parents_exists(path)
                if Path(os_path).exists() and os.path.getmtime(os_path) != clients_db.get_latest_update(path):
                    mess[counter] += " conflict!"
                    message[counter].set(mess[counter])
                    message_label[counter].after(5000, message_label[counter].destroy)
                    
                    print("receive conflict")
                    create_conflict(os_path)

                clients_db.update_object(path, -1, 1)
                open(os_path, "w")
                if new_update["size"] > 0:
                    s.send(bytes("send bytes", "utf-8"))
                    receive_data(new_update["path"], new_update["size"], s, new_update["latest_update"])
                elif new_update["size"] == 0:
                    fd = open(path, "rb+")
                    fd.truncate(0)
                    fd.close()
                    created_timestamp = os.stat(os_path).st_atime
                    os.utime(os_path, (created_timestamp, new_update["latest_update"]))
                clients_db.update_object(path, new_update["latest_update"], 0)
            elif new_update["action"] == 3:
                mess[counter] = "i received renamed : "+new_update["old_path"]+" -> "+new_update["new_path"]
                message[counter].set(mess[counter])
                
                db_old_path = new_update["old_path"]
                db_new_path = new_update["new_path"]
                latest_update = clients_db.get_latest_update(db_old_path)
                old_path = devices_path(db_old_path)
                new_path = devices_path(db_new_path)
                if not Path(old_path).exists():
                    mess[counter] += " done!"
                    message[counter].set(mess[counter])
                    message_label[counter].after(5000, message_label[counter].destroy)
                    
                    print("ignore move because the object don't exists")
                    s.send(bytes("completed", "utf-8"))
                    continue
                if Path(new_path).exists():
                    mess[counter] += " done!"
                    message[counter].set(mess[counter])
                    message_label[counter].after(5000, message_label[counter].destroy)
                    
                    print("ignore move because the new object exists")
                    s.send(bytes("completed", "utf-8"))
                    continue
                clients_db.update_object(db_old_path, -1, 1)
                os.rename(old_path, new_path)
                clients_db.rename_object(db_old_path, db_new_path)
                clients_db.update_object(db_new_path, latest_update, 1)
            elif new_update["action"] == 4:
                path = new_update["path"]
                mess[counter] = "i received deleted : "+new_update["path"]
                message[counter].set(mess[counter])
                
                path = new_update["path"]
                os_path = devices_path(path)
                if not Path(os_path).exists():
                    if clients_db.select_object(path) is not None:
                        clients_db.delete_object(path)
                    mess[counter] += " done!"
                    message[counter].set(mess[counter])
                    message_label[counter].after(5000, message_label[counter].destroy)
                    
                    s.send(bytes("completed", "utf-8"))
                    continue
                if new_update["latest_update"] != clients_db.get_latest_update(path) and clients_db.get_latest_update(
                        path) == os.path.getmtime(os_path):
                    print("ignore delete because did it on other (older or younger) file")
                    mess[counter] += " ignore!"
                    message[counter].set(mess[counter])
                    message_label[counter].after(5000, message_label[counter].destroy)
                    
                    s.send(bytes("completed", "utf-8"))
                    continue
                if Path(os_path).is_dir():
                    clients_db.update_object(path, -1, 1)
                    shutil.rmtree(os_path)
                else:
                    clients_db.update_object(path, -1, 1)
                    os.remove(os_path)
                clients_db.delete_object(path)
            elif new_update["action"] == 5:
                print("i receive all the renames")
                send_updates_sem.release()
            elif new_update["action"] == 6:
                print("i receive all the updates and deletes")
                send_deletes_sem.release()
            if new_update["action"] != 5 and new_update["action"] != 6:
                mess[counter] += " done!"
                message[counter].set(mess[counter])
                message_label[counter].after(5000, message_label[counter].destroy)  
            s.send(bytes("completed", "utf-8"))
        except:
            print("receiver finished")
            break


def update_server(s):
    send_updates_sem.acquire()
    if Path(username).exists():
        for (path, dirs, files) in os.walk(username):
            for (directory) in dirs:
                dev_path = devices_path(path + "/" + directory)
                db_path = linux_path(path + "/" + directory)
                if clients_db.select_object(db_path) is None:
                    objects_update = os.path.getmtime(dev_path)
                    new_update = {"action": 1, "path": db_path, "type": 1, "latest_update": objects_update}
                    send_message(s, new_update)
            for file in files:
                dev_path = devices_path(path + "/" + file)
                db_path = linux_path(path + "/" + file)
                db_latest_update = clients_db.get_latest_update(db_path)
                if db_latest_update is None:
                    objects_update = os.path.getmtime(dev_path)
                    objects_size = os.path.getsize(dev_path)
                    new_update = {"action": 1, "path": db_path, "type": 0, "latest_update": objects_update,
                                  "size": objects_size}
                    send_message(s, new_update)

                elif db_latest_update != os.path.getmtime(dev_path):
                    if db_latest_update > os.path.getmtime(dev_path):
                        created_timestamp = os.stat(dev_path).st_atime
                        os.utime(dev_path, (created_timestamp, db_latest_update))
                    else:
                        objects_update = os.path.getmtime(dev_path)
                        objects_size = Path(dev_path).stat().st_size
                        old_latest_update = clients_db.get_latest_update(db_path)
                        new_update = {"action": 2, "path": db_path, "latest_update": objects_update,
                                    "old_latest_update": old_latest_update, "size": objects_size}
                        send_message(s, new_update)
    new_update = {"action": 5}
    print("i send all the modifieds and creates")
    send_message(s, new_update)
    send_deletes_sem.acquire()
    folders = clients_db.select_all_folders()
    for folder in folders:
        os_path = devices_path(folder[0])
        if not Path(os_path).exists():
            new_update = {"action": 4, "path": folder[0], "latest_update": float(folder[1])}
            send_message(s, new_update)
    files = clients_db.select_all_files()
    for file in files:
        os_path = devices_path(file[0])
        if not Path(os_path).exists():
            new_update = {"action": 4, "path": file[0], "latest_update": float(file[1])}
            send_message(s, new_update)
    print("update server")
    send_deletes_sem.release()


def send_message(s, new_update):
    print("i send ", new_update)
    message = StringVar()
    global home_frame
    mes = ""
    if new_update["action"] == 1:
        mes = "i send create :"+new_update["path"]
    elif new_update["action"] == 2:
        mes = "i send modified :"+new_update["path"]
    elif new_update["action"] == 3:
        mes = "i send renamed : "+new_update["old_path"]+" -> "+new_update["new_path"]
    elif new_update["action"] == 4:
        mes = "i send deleted : "+new_update["path"]
    message.set(mes)
    message_label = Label(home_frame, textvariable=message,bg="black",fg="green", font=("calibri", 11))
    message_label.pack()
    s.send(bytes(json.dumps(new_update), "utf-8"))
    servers_response = s.recv(1024).decode("utf-8")
    if servers_response == "completed":
        message.set(mes+" done!")
        message_label.after(5000, message_label.destroy)
        print("i receive completed")
        if new_update["action"] == 1:
            if new_update["type"] == 1:
                clients_db.insert_object(new_update["path"], new_update["latest_update"], 1)
            else:
                clients_db.insert_object(new_update["path"], new_update["latest_update"], 0)
        elif new_update["action"] == 4:
            clients_db.delete_object(new_update["path"])
        elif new_update["action"] == 2:
            clients_db.update_object(new_update["path"], new_update["latest_update"], 0)
        elif new_update["action"] == 3:
            clients_db.rename_object(new_update["old_path"], new_update["new_path"])
    elif servers_response == "send bytes":
        send_all_bytes(new_update["path"], s, new_update["latest_update"])
        servers_response = s.recv(1024).decode("utf-8")
        if servers_response == "completed":
            message.set(mes+" done!")
            message_label.after(5000, message_label.destroy)
            print("bytes send completed")
            if new_update["action"] == 1:
                clients_db.insert_object(new_update["path"], new_update["latest_update"], 1)
            elif new_update["action"] == 2:
                clients_db.update_object(new_update["path"], new_update["latest_update"], 0)
    elif servers_response == "conflict":
        message.set(mes+" config!")
        message_label.after(5000, message_label.destroy)
        print("conflict files")
    elif servers_response == "ignore":
        message.set(mes+" ignore!")
        message_label.after(5000, message_label.destroy)
        print("ignore change")
    elif servers_response == "recreate":
        message.set(mes+" recreate!")
        message_label.after(5000, message_label.destroy)
        Path(devices_path(new_update["path"])).mkdir(True, True)
    elif servers_response == "send parent":
        message.set(mes+"resend!")
        message_label.after(5000, message_label.destroy)
        parent, child = new_update["path"].rsplit("/", 1)
        objects_update = os.path.getmtime(devices_path(parent))
        parent_update = {"action": 1, "path": parent, "type": 1, "latest_update": objects_update}
        send_message(s, parent_update)
        send_message(s, new_update)


def send_all_bytes(db_path, servers_socket, latest_update):
    object_path = devices_path(db_path)
    fd = open(object_path, "rb")
    file_bytes = fd.read(1024)
    file_list = list(file_bytes)
    while len(file_list) > 0:
        servers_socket.send(file_bytes)
        response = servers_socket.recv(1024)
        file_bytes = fd.read(1024)
        file_list = list(file_bytes)
    fd.close()
    #created_timestamp = os.stat(object_path).st_atime
    #os.utime(object_path, (created_timestamp, latest_update))



def send_updates():
    global username
    global mac
    global users_pass

    s = socket.socket()
    sockets.append(s)
    s.connect(('212.71.250.55', 8003))
    information = {"users_pass": users_pass, "username": username, "mac": mac}
    s.send(bytes(json.dumps(information), "utf-8"))
    print("sender send ", information)
    servers_response = s.recv(1024).decode("utf-8")
    if servers_response != "completed":
        print("not access")
        return
    update_server(s)
    while 1:
        try:
            new_update = actions_queue.get()
            print("send update get new update")
            if new_update["action"] == 2:
                new_update["old_latest_update"] = clients_db.get_latest_update(new_update["path"])
            elif new_update["action"] == 4:
                new_update["latest_update"] = clients_db.get_latest_update(new_update["path"])
            elif new_update["action"] == 1 and clients_db.select_object(new_update["path"]) is not None:
                continue
            elif new_update["action"] == 3 and clients_db.get_latest_update(new_update["old_path"]) == -1:
                continue
            send_message(s, new_update)
        except:
            print("Sender finished")
            break


class Event(FileSystemEventHandler):
    def on_created(self, event):
        if Path(event.src_path).name.startswith('~'):
            return
        path = event.src_path
        db_path = linux_path(path)
        print("created ", path)
        if clients_db.select_object(db_path) is not None: 
            print("watchdog:ignore, server did it ", path)
            return
        objects_update = os.path.getmtime(event.src_path)
        if Path(path).is_dir():
            new_update = {"action": 1, "path": db_path, "type": 1, "latest_update": objects_update}
        else:
            objects_size = os.path.getsize(path)
            new_update = {"action": 1, "path": db_path, "type": 0, "latest_update": objects_update,
                          "size": objects_size}

        actions_queue.put(new_update)

    def on_modified(self, event):
        new_update = "modified " + event.src_path
        print(new_update)
        if Path(event.src_path).name.startswith('~') or Path(event.src_path).is_dir():
            return
        path = event.src_path
        db_path = linux_path(path)
        db_latest_update = clients_db.get_latest_update(db_path)

        if db_latest_update is None or db_latest_update == -1 or db_latest_update == os.path.getmtime(event.src_path):
            print("watchdog 2:ignore, server did it ", db_path)
            return
        object_update = os.path.getmtime(event.src_path)
        if db_latest_update > object_update:
            created_timestamp = os.stat(event.src_path).st_atime
            os.utime(event.src_path, (created_timestamp, db_latest_update))
            return         
        objects_size = os.path.getsize(path)
        old_latest_update = clients_db.get_latest_update(db_path)
        new_update = {"action": 2, "path": db_path, "latest_update": object_update,
                      "old_latest_update": old_latest_update, "size": objects_size}
        actions_queue.put(new_update)

    def on_moved(self, event):
        print("moved ", event.src_path, " -> ", event.dest_path)
        if Path(event.src_path).name.startswith('~') or Path(event.dest_path).name.startswith('~'):
            return
        parent, old_path = event.src_path.rsplit(devices_slash(), 1)
        parent, new_path = event.dest_path.rsplit(devices_slash(), 1)
        if old_path == new_path:
            print("ignore: moved parent")
            return
        db_old_path = linux_path(event.src_path)
        db_new_path = linux_path(event.dest_path)
        latest_update = clients_db.get_latest_update(db_old_path)
        if latest_update is None or latest_update == -1:
            print("ignore: moved server did it")
            return
        new_update = {"action": 3, "old_path": db_old_path, "new_path": db_new_path}
        actions_queue.put(new_update)

    def on_deleted(self, event):
        if Path(event.src_path).name.startswith('~'):
            return
        print("deleted " + event.src_path)
        db_path = linux_path(event.src_path)
        objects_timestamp = clients_db.get_latest_update(db_path)
        if objects_timestamp is None or objects_timestamp == -1:
            print("watchdog: ignore, server did it")
            return
        new_update = {"action": 4, "path": db_path, "latest_update": clients_db.get_latest_update(db_path)}
        print("add to queue")
        actions_queue.put(new_update)


class SampleApp(Tk):
    def __init__(self, *args, **kwargs):
        global global_frames
        Tk.__init__(self, *args, **kwargs)

        self.title_font = tkfont.Font(family='Helvetica', size=18, weight="bold", slant="italic")
        self.title("Flsync")
        self.geometry("400x350")
        p1 = PhotoImage(file = 'icon.png')
        self.iconphoto(False, p1)
 
        
        # the container is where we'll stack a bunch of frames
        # on top of each other, then the one we want visible
        # will be raised above the others
        self.container = Frame(self)
        self.container.pack(side="top", fill="both", expand=True)
        self.container.grid_rowconfigure(0, weight=1)
        self.container.grid_columnconfigure(0, weight=1)

        self.frames = {}
        for F in (StartPage, Login, Register):
            page_name = F.__name__
            frame = F(parent=self.container, controller=self)
            self.frames[page_name] = frame

            # put all of the pages in the same location;
            # the one on the top of the stacking order
            # will be the one that is visible.
            frame.grid(row=0, column=0, sticky="nsew")

        global_frames = self.frames
        self.show_frame("StartPage")

    def show_frame(self, page_name):
        '''Show a frame for the given page name'''
        frame = self.frames[page_name]
        frame.tkraise()

    def create_frame(self, page_name):
        if page_name == "Home":
            frame = Home(parent=self.container, controller=self)
        else:
            frame = StartPage(parent=self.container, controller=self)
        frame.grid(row=0, column=0, sticky="nsew")
        frame.tkraise()

class StartPage(Frame):
    def __init__(self, parent, controller):
        Frame.__init__(self, parent)

        self.controller = controller
        label = Label(self, text="Welcome to Flsync",bg="black", fg="white" , font=controller.title_font)
        label.pack(side="top", fill="x", pady=50)
        button1 = Button(self, text="Login", width=10, height=1,bg='black', fg="white",
                        
                         command=lambda: controller.show_frame("Login"))
        button2 = Button(self, text="Register", width=10, height=1,bg='black', fg="white",
                         command=lambda: controller.show_frame("Register"))
        button1.pack()
        button2.pack()
        for thread in threading.enumerate():
            print(thread.name)
            print(thread.is_alive())
        self.configure(background='black')


def authentication_user(action, username_info, password_info, email_info):
    global username, mac, users_pass
    s = socket.socket()
    s.connect(('212.71.250.55', 8001))
    if action == "r":
        encoded_password = hashlib.md5(password_info.encode()).hexdigest()
        information = {"action": action, "username": username_info, "password": encoded_password, "email":email_info,"mac": mac}
        s.send(bytes(json.dumps(information), "utf-8"))
        response = s.recv(1024).decode("utf-8")
        s.close()
        if response != "username exists":
            users_pass = response
            username = username_info
            print(response)
            response = "ok"
        return response
    elif action == "l":
        encoded_password = hashlib.md5(password_info.encode()).hexdigest()
        information = {"action": action, "username": username_info, "password": encoded_password, "mac": mac}
        s.send(bytes(json.dumps(information), "utf-8"))
        response = s.recv(1024).decode("utf-8")
        s.close()
        if response != "username not exists" and response != "password not match":
            users_pass = response
            username = username_info
            print(response)
            response = "ok"
        return response


class Login(Frame):

    def __init__(self, parent, controller):
        self.error_message = StringVar()
        Frame.__init__(self, parent)
        self.controller = controller
        self.configure(background='black')
        
        button = Button(self, font=("Arial",12),
                        text="<" ,bg="black", fg="white",command=lambda: controller.show_frame("StartPage"))
        button.pack(side="top", anchor="nw")
        label = Label(self, text="Login", bg="black", fg="white",font=controller.title_font)
        label.pack(side="top", fill="x", pady=10)
        self.login_username = StringVar()
        self.login_password = StringVar()
        Label(self, text="Please enter details below", bg="black", fg="white").pack()
        Label(self, text="",bg="black").pack()
        Label(self, text="Username * ", bg="black", fg="white").pack()
        self.login_username_entry = Entry(self, textvariable=self.login_username)
        self.login_username_entry.pack()
        Label(self, text="Password * ", bg="black", fg="white").pack()
        self.login_password_entry = Entry(self, textvariable=self.login_password, show="*")
        self.login_password_entry.pack()
        Label(self, text="",bg="black").pack()
        self.login_button = Button(self, text="Login", width=10, height=1, bg="black", fg="white",
                                   command=self.login_user)
        self.login_button.pack()
        Label(self, textvariable=self.error_message,bg="black", fg="red", font=("calibri", 11)).pack()
        self.login_username_entry.bind('<Return>', lambda e: self.login_password_entry.focus_set())
        self.login_password_entry.bind('<Return>', lambda e: self.login_button.invoke())

    def login_user(self):
        global username
        username_info = self.login_username.get()
        password_info = self.login_password.get()
        print(username_info, " ", password_info)
        check_cred = authentication_user("l", username_info, password_info, "")
        if check_cred == "username not exists":
            self.login_username_entry.delete(0, END)
        elif check_cred == "ok":
            username = username_info
            self.controller.create_frame("Home")
        self.login_password_entry.delete(0, END)
        if check_cred != "ok":
            self.error_message.set(check_cred)


class Register(Frame):

    def __init__(self, parent, controller):
        Frame.__init__(self, parent)
        self.controller = controller
        self.configure(background='black')
        
        button = Button(self,  font=("Arial",12),
                        text="<" ,bg="black", fg="white",
                        command=lambda: controller.show_frame("StartPage"))
        button.pack(side="top", anchor="nw")
        label = Label(self, text="Register",bg="black", fg="white", font=controller.title_font)
        label.pack(side="top", fill="x", pady=10)

        self.register_username = StringVar()
        self.register_password = StringVar()
        self.register_email = StringVar()

        Label(self, text="Please enter details below",bg="black", fg="white",).pack()
        Label(self, text="",bg="black").pack()
        Label(self, text="Username * ",bg="black", fg="white").pack()
        self.register_username_entry = Entry(self, textvariable=self.register_username)
        self.register_username_entry.pack()
        Label(self, text="Password * ",bg="black", fg="white").pack()
        self.register_password_entry = Entry(self, textvariable=self.register_password, show="*")
        self.register_password_entry.pack()
        Label(self, text="Email * ",bg="black", fg="white").pack()
        self.register_email_entry = Entry(self, textvariable=self.register_email)
        self.register_email_entry.pack()
        Label(self, text="", bg="black").pack()
        self.register_button = Button(self, text="Register",bg="black", fg="white", width=10, height=1, command=self.register_user)
        self.register_button.pack()
        self.error_message = StringVar()
        Label(self, textvariable=self.error_message, bg="black",fg="red", font=("calibri", 11)).pack()
        self.register_username_entry.bind('<Return>', lambda e: self.register_password_entry.focus_set())
        self.register_password_entry.bind('<Return>', lambda e: self.register_button.invoke())

    def register_user(self):
        global username
        username_info = self.register_username.get()
        password_info = self.register_password.get()
        email_info = self.register_email.get()
        if username_info == "" or password_info == "" or email_info == "":
            self.error_message.set("complete all the entries")
        else:    
            self.register_email_entry.delete(0, END)
            self.register_username_entry.delete(0, END)
            self.register_password_entry.delete(0, END)
            check_cred = authentication_user("r", username_info, password_info, email_info)
            if check_cred == "ok":
                username = username_info
                self.controller.create_frame("Home")
            self.error_message.set(check_cred)


class Home(Frame):
    
    def __init__(self, parent, controller):
        global home_frame
        Frame.__init__(self, parent)
        home_frame = self
        self.configure(background='black')
        self.controller = controller
        self.message = StringVar()
        Label(self, textvariable=self.message,bg="black", fg="green", font=("calibri", 11)).pack()

        logout_button = Button(self, text="Logout", width=10, height=1,bg="black", fg="white",
                               command=self.logout)
        logout_button.pack()
        home_thread = Thread(target=self.home)
        home_thread.daemon = True
        home_thread.start()

    def home(self):
        global sockets, send_updates_sem, send_deletes_sem
        sockets = list()
        clients_db.create_connection(username)
        clients_db.create_tables()
        if not Path(username).exists():
            Path(username).mkdir(True, True)
        delete_destroyed_files()
        receive_updates_thread = Thread(target=receive_updates)
        receive_updates_thread.daemon = True
        receive_updates_thread.start()

        send_updates_thread = Thread(target=send_updates)
        send_updates_thread.daemon = True
        send_updates_thread.start()
        send_updates_sem = threading.Semaphore()
        send_deletes_sem = threading.Semaphore()

        self.message.set("Υou are logged in")

        send_updates_sem.acquire()
        send_deletes_sem.acquire()
        event_handler = Event()
        observer = Observer()
        observer.schedule(event_handler, path=username, recursive=True)
        observer.daemon = True
        observer.start()
        try:
            while True:
                time.sleep(0.001)
        except KeyboardInterrupt:
            observer.stop()
        print("home thread pro join")
        observer.join()
        print("home thread finished")

    def logout(self):
        os.execv(sys.executable, [sys.executable, __file__] + sys.argv)
        #os.execv(sys.argv[0], sys.argv)
        #os.system("python full_client.py")
        #os.startfile("full_client.py")
        #os.kill(os.getpid(), signal.SIGTERM)
    
if __name__ == "__main__":
    username = None 
    global users_pass
    global home_frame

    mac = str(get_mac())
    actions_queue = queue.Queue()
    global send_updates_sem, send_deletes_sem

    app = SampleApp()
    app.mainloop()

