import json, os ,platform, queue, shutil, socket,hashlib, threading, time, sys
from pathlib import Path
from threading import Thread
from uuid import getnode as get_mac
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent
import clients_db


def authentication_user():
    global username
    global users_pass
    global mac
    s = socket.socket()
    s.connect(('212.71.250.55', 8001))
    while 1:
        action = input('Login or Register(l or r): ')
        if action == "r":
            username = input('username : ')
            password = input('password : ')
            email = input('email :')
            encoded_password = hashlib.md5(password.encode()).hexdigest()
            information = {"action": action, "username": username,"email": email, "password": encoded_password, "mac": mac}
            s.send(bytes(json.dumps(information), "utf-8"))
            response = s.recv(1024).decode("utf-8")
            if response != "username exists":
                users_pass = response
                print("register ok")
                break
            else:
                print(response)
        elif action == "l":
            username = input('username : ')
            password = input('password : ')
            encoded_password = hashlib.md5(password.encode()).hexdigest()
            information = {"action": action, "username": username, "password": encoded_password, "mac": mac}
            s.send(bytes(json.dumps(information), "utf-8"))
            response = s.recv(1024).decode("utf-8")
            if response != "username not exists" and response != "password not match":
                users_pass = response
                print("login ok")
                break
            else:
                print(response)


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
    s = socket.socket()
    
    s.connect(('212.71.250.55', 8002))
    information = {"users_pass": users_pass, "username": username, "mac": mac}
    s.send(bytes(json.dumps(information), "utf-8"))
    print("receiver send ", information)
    while 1:
        try:
            new_message = s.recv(1024).decode("utf-8")
            new_update = json.loads(new_message)
            print("receive ", new_update)
            if new_update["action"] == 1:
                path = new_update["path"]
                os_path = devices_path(path)
                if Path(os_path).exists() and ((Path(os_path).is_dir()) or
                                               (clients_db.select_object(path) is not None and clients_db.get_latest_update(
                                                   path) == new_update["latest_update"])):
                    print("ignore message")
                    s.send(bytes("completed", "utf-8"))
                    continue

                check_parents_exists(path)
                if Path(os_path).exists() and clients_db.select_object(path) is not None and os.path.getmtime(
                        os_path) != clients_db.get_latest_update(path):
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
                os_path = devices_path(path)
                check_parents_exists(path)
                if Path(os_path).exists() and os.path.getmtime(os_path) != clients_db.get_latest_update(path):
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
                db_old_path = new_update["old_path"]
                db_new_path = new_update["new_path"]
                latest_update = clients_db.get_latest_update(db_old_path)
                old_path = devices_path(db_old_path)
                new_path = devices_path(db_new_path)
                if not Path(old_path).exists():
                    print("ignore move because the object don't exists")
                    s.send(bytes("completed", "utf-8"))
                    continue
                if Path(new_path).exists():
                    print("ignore move because the new object exists")
                    s.send(bytes("completed", "utf-8"))
                    continue
                clients_db.update_object(db_old_path, -1, 1)
                os.rename(old_path, new_path)
                clients_db.rename_object(db_old_path, db_new_path)
                clients_db.update_object(db_new_path, latest_update, 1)
            elif new_update["action"] == 4:
                path = new_update["path"]
                os_path = devices_path(path)
                if not Path(os_path).exists():
                    if clients_db.select_object(path) is not None:
                        clients_db.delete_object(path)
                    s.send(bytes("completed", "utf-8"))
                    continue
                if new_update["latest_update"] != clients_db.get_latest_update(path) and clients_db.get_latest_update(
                        path) == os.path.getmtime(os_path):
                    print("ignore delete because did it on other (older or younger) file")
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
    s.send(bytes(json.dumps(new_update), "utf-8"))
    servers_response = s.recv(1024).decode("utf-8")
    if servers_response == "completed":
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
            print("bytes send completed")
            if new_update["action"] == 1:
                clients_db.insert_object(new_update["path"], new_update["latest_update"], 1)
            elif new_update["action"] == 2:
                clients_db.update_object(new_update["path"], new_update["latest_update"], 0)
    elif servers_response == "conflict":
        print("conflict files")
    elif servers_response == "ignore":
        print("ignore change")
    elif servers_response == "recreate":
        Path(devices_path(new_update["path"])).mkdir(True, True)
    elif servers_response == "send parent":
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


if __name__ == '__main__':
    global username
    global users_pass
    mac = str(get_mac())
    actions_queue = queue.Queue()
    authentication_user()
    send_updates_sem = threading.Semaphore()
    send_updates_sem.acquire()
    send_deletes_sem = threading.Semaphore()
    send_deletes_sem.acquire()

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

    event_handler = Event()
    observer = Observer()
    observer.daemon = True
    observer.schedule(event_handler, path=username, recursive=True)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()