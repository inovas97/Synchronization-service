import mysql.connector


def get_connect():
    db = mysql.connector.connect(
        host="localhost",
        user="novas",
        password="novas6980263685",
    )
    dbcursor = db.cursor()
    dbcursor.execute("CREATE DATABASE IF NOT EXISTS novboxdb")
    dbcursor.close()
    db.database = "novboxdb"
    db.commit()
    return db


def close_connection(db):
    db.close()


def create_tables(db):
    dbcursor = db.cursor()
    dbcursor.execute("""CREATE table IF NOT EXISTS Users(username VARCHAR(30) PRIMARY KEY, password TEXT, email TEXT);""")
    dbcursor.execute("""CREATE table IF NOT EXISTS Objects(path VARCHAR(250),user VARCHAR(30),
    mac VARCHAR(30), 
    latest_update double, timestamp double, objects_type int , status int, objects_size int, new_path VARCHAR(250), 
    PRIMARY KEY(path, new_path) ,FOREIGN KEY (user) REFERENCES Users(username) ON DELETE CASCADE);""")
    dbcursor.execute("""CREATE table IF NOT EXISTS Devices(username VARCHAR(30), mac VARCHAR(30), timestamp double, 
    PRIMARY KEY(username, mac), FOREIGN KEY (username) REFERENCES Users(username) ON DELETE CASCADE);""")
    dbcursor.close()
    db.commit()


def insert_user(db, username, password, email):
    dbcursor = db.cursor()
    sql_query = """INSERT INTO Users(username, password, email) VALUES(%s,%s,%s)"""
    dbcursor.execute(sql_query, (username, password, email))
    dbcursor.close()
    db.commit()

def get_email(db, username):
    dbcursor = db.cursor()
    sql_query = """SELECT email FROM Users WHERE username = '%s' """ % username
    dbcursor.execute(sql_query)
    email = dbcursor.fetchone()
    dbcursor.close()
    if email is None:
        return None
    return email[0]
    

def login_user(db, username, password):
    dbcursor = db.cursor()
    sql_query = """SELECT password FROM Users WHERE username = '%s' """ % username
    dbcursor.execute(sql_query)
    user = dbcursor.fetchone()
    if user is None:
        print("Wrong username")
        dbcursor.close()
        return False
    users_password = user[0]
    if password != users_password:
        print("Wrong password")
        dbcursor.close()
        return False
    print("Successfully login")
    dbcursor.close()
    return True


def user_exists(db, username):
    dbcursor = db.cursor()
    sql_query = """SELECT username FROM Users WHERE username = '%s' """ % username
    dbcursor.execute(sql_query)
    user = dbcursor.fetchone()
    dbcursor.close()
    if user is None:
        print("don't exists")
        return False
    print("exists")
    return True


def update_password(db, username, password):
    dbcursor = db.cursor()
    sql_query= """UPDATE Users SET password = '%s' WHERE username = '%s'""" % (password, username)
    dbcursor.execute(sql_query)
    dbcursor.close()
    db.commit()


def insert_device(db, username, mac, timestamp):
    dbcursor = db.cursor()
    sql_query = """INSERT INTO Devices(username, mac, timestamp) VALUES(%s,%s,%s)"""
    dbcursor.execute(sql_query, (username, mac, timestamp))
    dbcursor.close()
    db.commit()


def devices_exists(db, username, mac):
    dbcursor = db.cursor()
    sql_query = """SELECT timestamp FROM Devices WHERE username = '%s' AND mac = '%s'""" % (username, mac)
    dbcursor.execute(sql_query)
    user = dbcursor.fetchone()
    dbcursor.close()
    if user is None:
        print("device don't exists")
        return False
    print("device exists")
    return True


def get_devices_timestamp(db, username, mac):
    dbcursor = db.cursor()
    sql_query = """SELECT timestamp FROM Devices WHERE username = '%s' AND mac = '%s'""" % (username, mac)
    dbcursor.execute(sql_query)
    timestamp = dbcursor.fetchone()
    dbcursor.close()
    return timestamp[0]


def update_devices_timestamp(db, username, mac, timestamp):
    dbcursor = db.cursor()
    sql_query = """UPDATE Devices SET timestamp = %s WHERE username = %s AND mac = %s"""
    dbcursor.execute(sql_query, (timestamp, username, mac))
    dbcursor.close()
    db.commit()


def insert_object(db, path, user, mac, latest_update, timestamp, objects_type, objects_size, status, new_path):
    objects_status = get_objects_status(db, path)
    if objects_status is not None:
        delete_object(db, path)
    dbcursor = db.cursor()
    sql_query = """INSERT INTO Objects(path, user, mac,latest_update, timestamp, objects_type, objects_size, status, new_path)
     VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)"""
    dbcursor.execute(sql_query, (path, user, mac, latest_update, timestamp, objects_type, objects_size, status, new_path))
    dbcursor.close()
    db.commit()
    update_parents(db, path, latest_update)


def get_objects_latest_update(db, path):
    dbcursor = db.cursor()
    sql_query = """SELECT latest_update FROM Objects WHERE path = '%s' AND new_path = ''""" % path
    dbcursor.execute(sql_query)
    timestamp = dbcursor.fetchone()
    if timestamp is None:
        return None
    return timestamp[0]


def get_users_younger_objects(db, username, timestamp):
    dbcursor = db.cursor()
    sql_query = """SELECT * FROM Objects WHERE user = %s AND timestamp > %s ORDER BY timestamp"""
    dbcursor.execute(sql_query, (username, timestamp))
    result = dbcursor.fetchall()
    dbcursor.close()
    return result


def get_users_renames(db, username, timestamp):
    dbcursor = db.cursor()
    sql_query = """SELECT * FROM Objects WHERE user = %s AND timestamp > %s AND status = 2 ORDER BY timestamp"""
    dbcursor.execute(sql_query, (username, timestamp))
    result = dbcursor.fetchall()
    dbcursor.close()
    return result


def update_objects_timestamp(db, path, timestamp):
    dbcursor = db.cursor()
    sql_query = """UPDATE Objects SET timestamp = %s WHERE path = %s AND new_path = ''"""
    dbcursor.execute(sql_query, (timestamp, path))
    dbcursor.close()
    db.commit()


def set_objects_status_live(db, path):
    dbcursor = db.cursor()
    sql_query = """UPDATE Objects SET status = 1 WHERE path = '%s' AND new_path = ''""" % path
    dbcursor.execute(sql_query)
    dbcursor.close()
    db.commit()


def get_objects_status(db, path):
    dbcursor = db.cursor()
    sql_query = """SELECT status FROM Objects WHERE path = '%s'  AND new_path = ''""" % path
    dbcursor.execute(sql_query)
    status = dbcursor.fetchone()
    dbcursor.close()
    if status is None:
        return None
    return status[0]


def update_objects_latest_update(db, path, latest_update):
    dbcursor = db.cursor()
    sql_query = """UPDATE Objects SET latest_update = %s WHERE path = %s  AND new_path = ''"""
    dbcursor.execute(sql_query, (latest_update, path))
    dbcursor.close()
    db.commit()


def update_objects_size(db, path, objects_size):
    dbcursor = db.cursor()
    sql_query = """UPDATE Objects SET objects_size = %s WHERE path = %s  AND new_path = ''"""
    dbcursor.execute(sql_query, (objects_size, path))
    dbcursor.close()
    db.commit()


def update_object(db, path, timestamp, mac, latest_update, objects_size):
    dbcursor = db.cursor()
    sql_query = """UPDATE Objects SET timestamp = %s, mac = %s, status = 1, latest_update = %s, objects_size = %s WHERE path = %s  
    AND new_path = ''"""
    dbcursor.execute(sql_query, (timestamp, mac, latest_update, objects_size, path))
    dbcursor.close()
    db.commit()
    update_parents(db, path, latest_update)


def update_parents(db, path, latest_update):
    parent, child = path.rsplit("/", 1)
    while "/" in parent:
        update_objects_latest_update(db, parent, latest_update)
        parent, child = parent.rsplit("/", 1)


def set_objects_status_deleted(db, path, timestamp, mac):
    dbcursor = db.cursor()
    sql_query = """UPDATE Objects SET status = 0, timestamp = %s , mac = %s WHERE path LIKE %s  AND new_path = ''"""
    dbcursor.execute(sql_query, (timestamp, mac, path+"%"))
    dbcursor.close()
    db.commit()


def delete_object(db, path):
    dbcursor = db.cursor()
    sql_query = """DELETE FROM Objects WHERE path LIKE '"""+path+"""%'  AND new_path = ''"""
    dbcursor.execute(sql_query)
    dbcursor.close()
    db.commit()


def get_all_children(db, path):
    dbcursor = db.cursor()
    sql_query = """SELECT * FROM Objects WHERE path LIKE '"""+path+"""%'  AND new_path = ''"""
    dbcursor.execute(sql_query)
    result = dbcursor.fetchall()
    dbcursor.close()
    return result


def get_folders_names(db, path):
    dbcursor = db.cursor()
    sql_query = """SELECT path FROM Objects WHERE path LIKE '"""+path+"""%'  
    AND new_path = '' AND status = 1 AND objects_type = 1"""
    dbcursor.execute(sql_query)
    result = dbcursor.fetchall()
    dbcursor.close()
    return result


def get_files_names(db, path):
    dbcursor = db.cursor()
    sql_query = """SELECT path FROM Objects WHERE path LIKE '"""+path+"""%'  
    AND new_path = '' AND status = 1 AND objects_type = 0"""
    dbcursor.execute(sql_query)
    result = dbcursor.fetchall()
    dbcursor.close()
    return result


def rename_object(db, old_path, replace_path, timestamp):
    children = get_all_children(db, old_path)
    for child in children:
        new_path = child[0].replace(old_path, replace_path)
        dbcursor = db.cursor()
        sql_query = """UPDATE Objects SET path = %s  WHERE path = %s AND status = 1  AND new_path = ''"""
        dbcursor.execute(sql_query, (new_path, child[0]))
        dbcursor.close()
        db.commit()
        if old_path == child[0]:
            insert_object(db, old_path, child[1], child[2], child[3], timestamp, child[5], child[6], 2, new_path)

'''
if __name__ == '__main__':
    create_db()
    create_tables()
    get_devices_timestamp("novas", "123456789")
'''