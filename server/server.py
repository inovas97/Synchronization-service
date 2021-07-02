import json, os, queue, shutil, socket, string, threading, time, random
from pathlib import Path
import servers_db
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread

devices = {}
send_updates_deletes = {}
connections_pass = {}


def linux_path(path):
    return path.replace("\\", "/")


def authentication_user(client_socket):
    db = servers_db.get_connect()
    while 1:
        try:
            new_message = client_socket.recv(1024)
            new_message = json.loads(new_message.decode())
            print(new_message)
            action, username, password, mac = new_message["action"], new_message["username"], new_message["password"], new_message["mac"]
            if action == "r":
                email = new_message['email']
                if servers_db.user_exists(db, username):
                    client_socket.send(bytes("username exists", "utf-8"))
                else:
                    Path(username).mkdir(parents=True, exist_ok=True)
                    os.chmod(username, 0o777)
                    servers_db.insert_user(db, username, password, email)
                    if mac != 1:
                        conn_pass = ''.join(random.choices(string.ascii_uppercase + string.digits, k=16))
                        connections_pass[username, mac] = conn_pass
                        client_socket.send(bytes(conn_pass, "utf-8"))
                    else:
                        client_socket.send(bytes("ok", "utf-8"))
                    print("successfully register")
                    servers_db.close_connection(db)
                    return
            else:
                if not servers_db.user_exists(db, username):
                    client_socket.send(bytes("username not exists", "utf-8"))
                elif not servers_db.login_user(db, username, password):
                    client_socket.send(bytes("password not match", "utf-8"))
                else:
                    if mac != 1:
                        conn_pass = ''.join(random.choices(string.ascii_uppercase + string.digits, k=16))
                        connections_pass[username, mac] = conn_pass
                        client_socket.send(bytes(conn_pass, "utf-8"))
                    else:
                        client_socket.send(bytes("ok", "utf-8"))
                    print("successfully login")
                    servers_db.close_connection(db)
                    time.sleep(10)
                    return
        except:
            print("An exception occurred")
            return


def create_temp_parents(path):
    parent, child = path.rsplit("/", 1)
    if not Path(parent).exists():
        create_temp_parents(parent)
        Path(parent).mkdir(True, True)
        os.chmod(parent, 0o777)


def receive_data(object_path, filesize, receive_socket):
    try:
        temp_object_path = "temp/" + object_path
        create_temp_parents(temp_object_path)
        open(temp_object_path, "w")
        received_bytes = 0
        fd = open(temp_object_path, "rb+")
        while filesize > received_bytes:
            to_write = receive_socket.recv(1024)
            fd.seek(int(received_bytes), 0)
            wrote = fd.write(to_write)
            receive_socket.send(bytes("ok", "utf-8"))
            received_bytes += len(to_write)
            
        fd.truncate(filesize)
        fd.close()
        if Path(object_path).exists():
            os.remove(object_path)
        parent, child = object_path.rsplit("/", 1)
        shutil.move(temp_object_path, parent)
        print("file upload ok")
        return True
    except:
        print("Error to receive file")
        return False


def forward_update_to_other_devices(username, mac, actions_timestamp, new_update):
    keys = devices.keys()
    users_others_devices = []
    for key in keys:
        if username in key and mac not in key:
            users_others_devices.append(key)
    for other_device in users_others_devices:
        devices[other_device].put((actions_timestamp, new_update))


def check_for_rebuild_parents(db, path, timestamp, username, mac, latest_update):
    parent, child = path.rsplit("/", 1)
    print(parent)
    if not Path(parent).exists():
        actions_timestamp = timestamp - 1
        check_for_rebuild_parents(db, parent, actions_timestamp, username, mac, latest_update)
        print("try create ", parent)
        if servers_db.get_objects_status(db, parent) is None:
            servers_db.insert_object(db, parent, username, mac, latest_update, actions_timestamp, 1, 0, 1, "")
        else:
            servers_db.update_object(db, parent, actions_timestamp, mac, latest_update, 0)
            # servers_db.set_objects_status_live(parent)
        Path(parent).mkdir(True, True)
        os.chmod(parent, 0o777)
        print("created ", parent)
        new_update = {"action": 1, "path": parent, "type": 1, "latest_update": latest_update}
        forward_update_to_other_devices(username, mac, actions_timestamp, new_update)


def receive_updates(client_socket):
    db = servers_db.get_connect()
    new_message = client_socket.recv(1024)
    new_message = json.loads(new_message.decode("utf-8"))
    conn_pass, username, mac = new_message['users_pass'], new_message['username'], new_message['mac']
    if connections_pass[username, mac] != conn_pass:
        print("not access for this user")
        client_socket.send(bytes("not access", "utf-8"))
        return
    if (username, mac) not in devices.keys():
        devices[username, mac] = queue.Queue()
        send_updates_deletes[username, mac] = threading.Semaphore()
        send_updates_deletes[username, mac].acquire()
    print("receive from this device ok")
    client_socket.send(bytes("completed", "utf-8"))
    while 1:
        try:
            new_message = client_socket.recv(1024).decode("utf-8")
            new_update = json.loads(new_message)
            print("i receive ", new_update)
            actions_timestamp = time.time()
            # created
            if new_update["action"] == 1:
                path = new_update["path"]
                check_for_rebuild_parents(db, path, actions_timestamp, username, mac, new_update["latest_update"])
                objects_size = 0
                if new_update["type"] == 1:
                    if not Path(path).exists():
                        Path(path).mkdir(True, True)
                        os.chmod(path, 0o777)
                else:
                    objects_size = new_update["size"]
                    open(path, "w")
                    status = servers_db.get_objects_status(db, path)
                    if status is not None and status == 1:
                        print("conflict")
                        client_socket.send(bytes("conflict", "utf-8"))
                        continue
                    if new_update["size"] > 0:
                        print("ask to send bytes")
                        client_socket.send(bytes("send bytes", "utf-8"))
                        if not receive_data(new_update["path"], new_update["size"], client_socket):
                            return
                created_timestamp = os.path.getctime(path)
                os.utime(path, (created_timestamp, new_update["latest_update"]))
                if servers_db.get_objects_status(db, path) is None:
                    servers_db.insert_object(db, new_update["path"], username, mac, new_update["latest_update"],
                                             actions_timestamp, new_update["type"], objects_size, 1, "")
                else:
                    servers_db.update_object(db, path, actions_timestamp, mac, new_update["latest_update"],
                                             objects_size)
                    servers_db.set_objects_status_live(db, path)
            # modified
            elif new_update["action"] == 2:
                path = new_update["path"]
                if servers_db.get_objects_status(db, path) == 1:
                    if new_update["old_latest_update"] != servers_db.get_objects_latest_update(db, path):
                        print("conflict")
                        client_socket.send(bytes("conflict", "utf-8"))
                        continue

                check_for_rebuild_parents(db, path, actions_timestamp, username, mac, new_update["latest_update"])
                if not Path(path).exists():
                    open(path, "w")
                if new_update["size"] > 0:
                    client_socket.send(bytes("send bytes", "utf-8"))
                    if not receive_data(new_update["path"], new_update["size"], client_socket):
                        return
                elif new_update["size"] == 0:
                    fd = open(path, "rb+")
                    fd.truncate(0)
                    fd.close()
                created_timestamp = os.path.getctime(path)
                os.utime(path, (created_timestamp, new_update["latest_update"]))
                servers_db.update_object(db, path, actions_timestamp, mac, new_update["latest_update"],
                                         new_update["size"])
            # moved
            elif new_update["action"] == 3:
                if Path(new_update["old_path"]).exists():
                    os.rename(new_update["old_path"], new_update["new_path"])
                    servers_db.rename_object(db, new_update["old_path"], new_update["new_path"], actions_timestamp)
                else:
                    client_socket.send(bytes("completed", "utf-8"))
                    continue
            # deleted
            elif new_update["action"] == 4:
                path = new_update["path"]
                if not Path(path).exists():
                    servers_db.set_objects_status_deleted(db, path, actions_timestamp, mac)
                    client_socket.send(bytes("completed", "utf-8"))
                    continue
                if new_update["latest_update"] != servers_db.get_objects_latest_update(db, path):
                    if Path(path).is_dir():
                        client_socket.send(bytes("recreate", "utf-8"))
                    else:
                        client_socket.send(bytes("ignore", "utf-8"))
                    print("ignore delete because did it to a old file")
                    print(new_update["latest_update"], " ", servers_db.get_objects_latest_update(db, path))
                    continue
                if Path(path).is_dir():
                    shutil.rmtree(path)
                else:
                    os.remove(path)
                servers_db.set_objects_status_deleted(db, path, actions_timestamp, mac)
            elif new_update["action"] == 5:
                send_updates_deletes[username, mac].release()
                client_socket.send(bytes("completed", "utf-8"))
                continue
            forward_update_to_other_devices(username, mac, actions_timestamp, new_update)
            client_socket.send(bytes("completed", "utf-8"))

        except socket.error as exc:
            del devices[username, mac]
            servers_db.close_connection(db)
            print(username, " Caught exception socket.error : %s" % exc)
            break
        except:
            del devices[username, mac]
            servers_db.close_connection(db)
            print(" Caught exception")
            break


def update_device(db, username, mac, client_socket, devices_timestamp):
    renames = servers_db.get_users_renames(db, username, devices_timestamp)
    for to_send in renames:
        if to_send[2] != mac:
            new_update = {"action": 3, "old_path": to_send[0], "new_path": to_send[8]}
            if not send_message(client_socket, new_update):
                return False
    new_update = {"action": 5}
    if not send_message(client_socket, new_update):
        return False
    send_updates_deletes[username, mac].acquire()
    objects_to_send = servers_db.get_users_younger_objects(db, username, devices_timestamp)
    for to_send in objects_to_send:
        if to_send[2] != mac:
            # status == 1 live
            if to_send[6] == 1:
                new_update = {"action": 1, "path": to_send[0], "type": to_send[5], "latest_update": to_send[3],
                              "size": to_send[7]}
                if not send_message(client_socket, new_update):
                    return False
            # status == 0 deleted
            elif to_send[6] == 0:
                new_update = {"action": 4, "path": to_send[0], "latest_update": to_send[3]}
                if not send_message(client_socket, new_update):
                    return False
        servers_db.update_devices_timestamp(db, username, mac, to_send[4])
    new_update = {"action": 6}
    if not send_message(client_socket, new_update):
        return False
    return True


def send_all_bytes(object_path, clients_socket):
    try:
        fd = open(object_path, "rb")
        file_bytes = fd.read(1024)
        file_list = list(file_bytes)
        while len(file_list) > 0:
            clients_socket.send(file_bytes)
            response = clients_socket.recv(1024)
            file_bytes = fd.read(1024)
            file_list = list(file_bytes)
        fd.close()
        return True
    except:
        print("file's sending except")
        return False


def send_message(client_socket, new_update):
    try:
        client_socket.send(bytes(json.dumps(new_update), "utf-8"))
        print("i send ", new_update)
        client_response = client_socket.recv(1024).decode("utf-8")
        if client_response == "completed":
            print("device receive successfully")
            return True
        elif client_response == "send bytes":
            if send_all_bytes(new_update["path"], client_socket):
                client_response = client_socket.recv(1024).decode("utf-8")
                if client_response == "completed":
                    print("bytes send completed")
                    return True
            return False
        return False
    except:
        return False


def send_updates(client_socket):
    db = servers_db.get_connect()
    new_message = client_socket.recv(1024)
    new_message = json.loads(new_message.decode())
    conn_pass, username, mac = new_message["users_pass"], new_message['username'], new_message['mac']
    if connections_pass[username, mac] != conn_pass:
        print("not access for this user")
        return
    print("access ok")
    if (username, mac) not in devices.keys():
        devices[username, mac] = queue.Queue()
        send_updates_deletes[username, mac] = threading.Semaphore()
        send_updates_deletes[username, mac].acquire()
    devices_timestamp = 0
    if servers_db.devices_exists(db, username, mac):
        devices_timestamp = servers_db.get_devices_timestamp(db, username, mac)
    else:
        servers_db.insert_device(db, username, mac, 0)
    update_device(db, username, mac, client_socket, devices_timestamp)
    while 1:
        actions_timestamp, new_update = devices[username, mac].get()
        if send_message(client_socket, new_update):
            servers_db.update_devices_timestamp(db, username, mac, actions_timestamp)
        else:
            return


def upload_from_web(client_socket):
    db = servers_db.get_connect()
    new_message = client_socket.recv(1024)
    new_message = json.loads(new_message.decode("utf-8"))
    print("web: ", new_message)
    actions_timestamp = time.time()
    path = new_message["path"]
    secure_path = new_message["secure_path"]
    if secure_path != path:
        if Path(path).exists():
            os.remove(path)
        os.rename(secure_path, path)
    username = new_message["user"]
    latest_update = os.path.getmtime(path)
    check_for_rebuild_parents(db, path, actions_timestamp, username, 0, latest_update)
    objects_type = 0
    objects_size = os.path.getsize(path)
    if Path(path).is_dir():
        os.chmod(path, 0o777)
        objects_type = 1
    objects_status = servers_db.get_objects_status(db, path)
    if objects_status is not None and objects_status == 1:
        old_latest_update = servers_db.get_objects_latest_update(db, path)
        servers_db.update_object(db, path, actions_timestamp, 0, latest_update, objects_size)
        servers_db.set_objects_status_live(db, path)

        new_update = {"action": 2, "path": path, "latest_update": latest_update,
                      "old_latest_update": old_latest_update, "size": objects_size}
    else:
        servers_db.insert_object(db, path, username, 0, latest_update,
                                 actions_timestamp, objects_type, objects_size, 1, "")
        new_update = {"action": 1, "path": path, "type": objects_type, "latest_update": latest_update,
                      "size": objects_size}

    client_socket.send(bytes("completed", "utf-8"))
    forward_update_to_other_devices(username, 0, actions_timestamp, new_update)


def create_connection_for_auth():
    soc = socket.socket()
    soc.bind(('212.71.250.55', 8001))
    soc.listen(5)
    while 1:
        client_socket, address = soc.accept()
        t1 = Thread(target=authentication_user, args=[client_socket])
        t1.start()

        '''
        keys = users.keys()
        if username not in keys:
            users[username] = threading.Semaphore()
        '''
        # t1 = Thread(target=receive_message, args=[username, mac, client_socket, address])
        # t1.start()
        # client_socket.send(bytes("ok", "utf-8"))


def create_connection_to_receive_updates():
    soc = socket.socket()
    soc.bind(('212.71.250.55', 8003))
    soc.listen(5)
    while 1:
        client_socket, address = soc.accept()
        t1 = Thread(target=receive_updates, args=[client_socket])
        t1.start()


def create_connection_to_send_updates():
    soc = socket.socket()
    soc.bind(('212.71.250.55', 8002))
    soc.listen(5)
    while 1:
        client_socket, address = soc.accept()
        t1 = Thread(target=send_updates, args=[client_socket])
        t1.start()


def create_connection_to_upload_from_web():
    soc = socket.socket()
    soc.bind(('212.71.250.55', 8004))
    soc.listen(5)
    while 1:
        client_socket, address = soc.accept()
        t1 = Thread(target=upload_from_web, args=[client_socket])
        t1.start()


class Message(BaseHTTPRequestHandler):
    print("ok")


def main():
    if not Path("temp").exists():
        Path("temp").mkdir(True, True)
        os.chmod("temp", 0o777)
    if not Path("web").exists():
        Path("web").mkdir(True, True)
        os.chmod("web", 0o777)
    PORT = 8080
    # server_ip = '127.0.0.1'
    server_ip = '212.71.250.55'
    # server_ip = socket.gethostbyname(server)
    db = servers_db.get_connect()
    servers_db.create_tables(db)
    servers_db.close_connection(db)
    # thread to send updates
    cctsu_thread = Thread(target=create_connection_to_send_updates)
    cctsu_thread.start()

    # thread to receive updates
    cctru_thread = Thread(target=create_connection_to_receive_updates)
    cctru_thread.start()

    # thread tautopoihsh xrhstwn
    connect_client_thread = Thread(target=create_connection_for_auth)
    connect_client_thread.start()

    web_thread = Thread(target=create_connection_to_upload_from_web)
    web_thread.start()

    server_address = (server_ip, PORT)
    server = HTTPServer(server_address, Message)
    print('Server running on port %s' % PORT)
    server.serve_forever()


if __name__ == '__main__':
    main()
