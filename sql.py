import sqlite3
import sql
import functionLibrary
import bcrypt


# This class is a simple handler for all of our SQL database actions
# Practicing a good separation of concerns, we should only ever call
# These functions from our models

# If you notice anything out of place here, consider it to your advantage and don't spoil the surprise

class SQLDatabase():
    '''
        Our SQL Database

    '''

    # Get the database running
    def __init__(self, database_arg=":memory:"):
        self.conn = sqlite3.connect(database_arg)
        self.cur = self.conn.cursor()

    # SQLite 3 does not natively support multiple commands in a single statement
    # Using this handler restores this functionality
    # This only returns the output of the last command
    def execute(self, sql_string):
        out = None
        for string in sql_string.split(";"):
            try:
                out = self.cur.execute(string)
            except:
                pass
        return out

    # Commit changes to the database
    def commit(self):
        self.conn.commit()

    # -----------------------------------------------------------------------------

    # Sets up the database
    # Default admin password
    def user_database_setup(self, admin_password='admin'):
        # Add user table at the first.
        # Clear the database if needed
        self.execute("DROP TABLE IF EXISTS Users")
        self.execute("DROP TABLE IF EXISTS Friends")
        self.execute("DROP TABLE IF EXISTS Messages")
        self.commit()

        # Create the users table
        self.execute("""CREATE TABLE Users(
             Id INTEGER PRIMARY KEY AUTOINCREMENT,
             username TEXT,
             hashedPassword TEXT,
             public_key VARCHAR(2048),
             private_key VARCHAR(2048),
             admin INTEGER DEFAULT 0,
             muted INTEGER DEFAULT 0
         )""")

        self.execute("""CREATE TABLE Friends(
             Id_1 INTEGER,
             Id_2 INTEGER,
             PRIMARY KEY(Id_1,Id_2)
         )""")

        self.execute("""CREATE TABLE Messages(
             Id INTEGER PRIMARY KEY AUTOINCREMENT,
             sender TEXT,
             receiver TEXT,
             Message VARCHAR(8192),
             Signature TEXT,
             Timestamp INTEGER
         )""")

        self.execute("""CREATE TABLE Resources(
             Id INTEGER PRIMARY KEY AUTOINCREMENT,
             Title TEXT,
             Poster TEXT,
             Description VARCHAR(8192),
             Link VARCHAR(1024),
             Timestamp INTEGER
         )""")

        self.commit()

        # Hash and salt the password
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(admin_password.encode('utf-8'), salt)

        # Generate the public and private keys
        publicKey, privateKey = functionLibrary.generate_keys()

        #Add admin user
        self.add_user('admin', hashed_password, publicKey, privateKey, 1)

    # -----------------------------------------------------------------------------
    # User handling
    # -----------------------------------------------------------------------------

    # Add a user to the database
    def add_user(self, username, hashed_password, publicKey, privateKey, admin=0):

        hashed_password_hex = hashed_password.hex()
        #print(type(hashed_password))
        sql_cmd = """
                 INSERT INTO Users
                 VALUES(null, '{username}', '{hashedPassword}', '{public_key}', '{private_key}', {admin}, 0)
             """.format(username=username, hashedPassword=hashed_password_hex, public_key=publicKey, private_key=privateKey, admin=admin)

        self.execute(sql_cmd)
        self.commit()

    def delete_user(self, username):
        uid = self.get_user(username)[0]

        #Delete user from user list
        sql_cmd = """
             DELETE FROM Users
             WHERE username='{username}'
             """.format(username=username)
        self.execute(sql_cmd)

        #Delete relevant friends
        sql_cmd = """
             DELETE FROM Friends
             WHERE Id_1={int_1} OR Id_2={int_2}
             """.format(int_1=uid, int_2=uid)
        self.execute(sql_cmd)

        #Delete relevant Messages
        sql_cmd = """
             DELETE FROM Messages
             WHERE sender='{sender}' OR receiver='{receiver}'
             """.format(sender=username, receiver=username)
        self.execute(sql_cmd)
        self.commit()

    # if set_muted is 0, user can speak, if it is 1, it is muted
    def mute_user(self, username, set_muted: int):
        sql_cmd = """
             UPDATE Users
             SET muted = {set_muted}
             WHERE username='{username}'
         """.format(set_muted=set_muted, username=username)
        self.execute(sql_cmd)
        self.commit()

    def is_user_muted(self, username):
        sql_cmd = """
             SELECT * FROM Users
             WHERE username='{username}'
        """.format(username=username)

        self.execute(sql_cmd)
        result = self.cur.fetchone()

        if result is None:
            print("Is User Muted: No Such User")
            return
        if result[6] == 0:
            return False
        else:
            return True


    def search_table(self, table_name, target_field_name, target_value):
        '''
            Search the table given a field name and a target value
            Returns the first entry found that matches

        # Lazy search for matching entries
        for entry in self.entries:
            for field_name, value in zip(self.fields, entry):
                if target_field_name == field_name and target_value == value:
                    return entry
                    '''

        sql_cmd = """
                 SELECT * 
                 FROM {table_name}
                 WHERE {field_name}='{value}'
             """.format(table_name=table_name, field_name=target_field_name, value=target_value)

        self.execute(sql_cmd)

        result = self.cur.fetchone()

        return result

    def get_user(self, username):
        checkValidUser_query = """
             SELECT *
             FROM Users
             WHERE username = '{name}'
         """.format(name=username)
        self.execute(checkValidUser_query)

        result = self.cur.fetchone()

        return result

    def get_user_by_id(self, id):
        query = """
             SELECT *
             FROM Users
             WHERE id = {}
         """.format(id)
        self.execute(query)

        result = self.cur.fetchone()

        return result


    def add_friend(self, id1, id2):
        query = """
             INSERT INTO Friends
             VALUES({id_1},{id_2})
         """.format(id_1=id1, id_2=id2)
        self.execute(query)
        self.commit()

    def get_targetfriend(self, id1, id2):
        if id1 > id2:
            tem = id1
            id1 = id2
            id2 = tem

        query = """
             SELECT * FROM Friends
             WHERE Id_1={id_1} AND Id_2={id_2}
         """.format(id_1=id1, id_2=id2)
        self.execute(query)
        result = self.cur.fetchone()
        return result

    def get_friends(self, id):
        query = """
             SELECT * FROM Friends
             WHERE Id_1={int_1} OR Id_2={int_2}
         """.format(int_1=id,int_2=id)
        #WHERE Id_1={i1} OR Id_2={i2}
        #.format(i1=id, i2=id)
        self.execute(query)
        result = self.cur.fetchall()
        return result

    def add_message(self, username, user_to, message, signature, timestamp):
        query = """
            INSERT INTO Messages
            VALUES(null, '{sender}', '{receiver}', '{message}', '{signature}', {timestamp})
        """.format(sender=username, receiver=user_to, message=message, signature=signature, timestamp=timestamp)
        self.execute(query)
        self.commit()

    def get_allmessages(self, sender, receiver):
        query = """
             SELECT * FROM Messages
             WHERE sender='{sender}' AND receiver='{receiver}'
         """.format(sender=sender,receiver=receiver)

        self.execute(query)
        result = self.cur.fetchall()
        return result

    def add_resource(self, title, poster_name, description, link, timestamp):
        query = """
            INSERT INTO Resources
            VALUES(null, '{title}', '{poster}', '{description}', '{link}', {timestamp})
        """.format(title=title, poster=poster_name, description=description, link=link, timestamp=timestamp)

        self.execute(query)
        self.commit()

    # -----------------------------------------------------------------------------

    # Check login credentials


database_args = "UserDatabase.db"
sql_db = sql.SQLDatabase(database_args)

query = """
     SELECT *
     FROM Users
 """
sql_db.execute(query)
print(sql_db.cur.fetchall())

query = """
     SELECT *
     FROM Friends
 """
sql_db.execute(query)
print("Friends:")
print(sql_db.cur.fetchall())

query = """
     SELECT *
     FROM Messages
"""
sql_db.execute(query)
print("Messages:")
print(sql_db.cur.fetchall())

query = """
     SELECT *
     FROM Resources
"""
sql_db.execute(query)
print("Resources:")
print(sql_db.cur.fetchall())
