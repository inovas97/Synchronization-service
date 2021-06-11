import sqlite3
from sqlite3 import Error
import decimal
# create a new context for this task
ctx = decimal.Context()

# 20 digits should be enough for everyone :D
ctx.prec = 20
db_file = ""


def float_to_str(f):
    """
    Convert the given float to a string,
    without resorting to scientific notation
    """
    d1 = ctx.create_decimal(repr(f))
    return format(d1, 'f')


def create_connection(db_filename):
    global db_file
    db_file = db_filename+".db"


def create_tables():
    try:
        conn = sqlite3.connect(db_file)
        conn.execute(""" CREATE TABLE IF NOT EXISTS Objects(
                                        path text PRIMARY KEY,
                                        latest_update TEXT,
                                        type int
                                        );""")
    except Error as e:
        print(e)
        return False


def insert_object(path, latest_update, objects_type):
    global db_file
    conn = sqlite3.connect(db_file)
    insert_sql = """INSERT INTO Objects VALUES(?, ?, ?);"""
    conn.execute(insert_sql, (path, float_to_str(latest_update), objects_type))
    conn.commit()
    update_parents(path, latest_update)


def update_object(path, latest_update, only_this):
    global db_file
    conn = sqlite3.connect(db_file)

    update_sql = """ UPDATE Objects
              SET latest_update = ?
              WHERE path = ?"""
    conn.execute(update_sql, (float_to_str(latest_update), path))
    conn.commit()
    if latest_update != -1:
        update_parents(path, latest_update)
    if not only_this:
        update_parents(path, latest_update)


def delete_object(path):
    global db_file
    conn = sqlite3.connect(db_file)
    delete_sql = """DELETE FROM Objects WHERE path LIKE '"""+path+"""%'"""
    conn.execute(delete_sql)
    conn.commit()


def rename_object(old_path, new_path):
    global db_file
    conn = sqlite3.connect(db_file)
    rename_sql = """UPDATE Objects SET path = replace(path, ? ,?) WHERE path LIKE '"""+old_path+"""%'"""
    conn.execute(rename_sql, (old_path, new_path))
    conn.commit()


def select_all_folders():
    global db_file
    conn = sqlite3.connect(db_file)
    cur = conn.cursor()
    cur.execute("SELECT * FROM Objects WHERE type = 1 ORDER BY path")
    rows = cur.fetchall()
    return rows


def select_all_files():
    global db_file
    conn = sqlite3.connect(db_file)
    cur = conn.cursor()
    cur.execute("SELECT * FROM Objects WHERE type = 0 ORDER BY path")
    rows = cur.fetchall()
    return rows


def select_object(path):
    global db_file
    conn = sqlite3.connect(db_file)
    sql_select = """SELECT * FROM Objects WHERE path = '"""+path+"""'"""
    cur = conn.cursor()
    cur.execute(sql_select)
    rows = cur.fetchall()
    if len(rows) == 0:
        return None
    return rows[0]


def get_latest_update(path):
    result = select_object(path)
    if result is None:
        return None
    return float(result[1])


def update_parents(path, latest_update):
    parent, child = path.rsplit("/", 1)
    while "/" in parent:
        update_object(parent, latest_update, 1)
        parent, child = parent.rsplit("/", 1)


def select_destroyed_files():
    global db_file
    conn = sqlite3.connect(db_file)
    cur = conn.cursor()
    cur.execute("SELECT * FROM Objects WHERE latest_update = -1")
    rows = cur.fetchall()
    return rows
