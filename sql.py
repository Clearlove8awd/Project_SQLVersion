import sqlite3
from Crypto.Hash import MD5


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
        self.commit()

        # Create the users table
        self.execute("""CREATE TABLE Users(
             Id INTEGER PRIMARY KEY AUTOINCREMENT,
             username TEXT,
             hashedPassword TEXT,
             public_key VARCHAR,
             private_key VARCHAR,
             admin INTEGER DEFAULT 0
         )""")

        self.commit()

        # Add our admin user

        # Hash and salt the password
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)

        # Generate the public and private keys
        publicKey, privateKey = generate_keys()

        self.add_user('admin', admin_password, admin=1)

    # -----------------------------------------------------------------------------
    # User handling
    # -----------------------------------------------------------------------------

    # Add a user to the database
    def add_user(self, username, hashed_password, publicKey, privateKey, admin=0):

        # first make sure that the user name does not exist.
        checkValidUser_query = """
             SELECT *
             FROM Users
             WHERE username = '{username}'
         """.format(username=username)

        self.execute(checkValidUser_query)

        # if the user does not exist, we can add this user
        if self.cur.fetchone() is None:
            sql_cmd = """
                     INSERT INTO Users
                     VALUES(null, '{username}', '{hashedPassword}', '{public_key}', 'private_key', {admin})
                 """

            sql_cmd = sql_cmd.format(username=username, hashedPassword=hashed_password, public_key=publicKey,
                                     private_key=privateKey, admin=admin)

            self.execute(sql_cmd)
            self.commit()
            return True
        else:
            print("Error, the user has been in")
            return False

    # -----------------------------------------------------------------------------

    # Check login credentials
    def check_credentials(self, username, password):

        getSalt_query = """
                SELECT *
                FROM Users
                WHERE username = '{username}'
            """
        getSalt_query = getSalt_query.format(username=username)
        self.cur.execute(getSalt_query)
        returnValue = self.cur.fetchone()

        if (returnValue == None):
            return "NoSuchUserName"
        else:
            salt = returnValue[3]

        # Now we got salt, then get the corresponding hashed password
        passwordByHash = MD5.new((password + salt).encode()).hexdigest()

        # Compare the hashed password with the hashed password in database
        sql_query = """
                SELECT *
                FROM Users
                WHERE username = '{username}' AND password = '{password}'
            """
        sql_query = sql_query.format(username=username, password=passwordByHash)
        self.cur.execute(sql_query)

        # If our query returns
        if self.cur.fetchone():
            return "UserExistAndPasswordCorrect"
        else:
            return "PasswordIncorrect"

