import sqlite3
import sql
import functionLibrary
import bcrypt
import datetime


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

        # self.execute("""CREATE TABLE Resources(
        #      Id INTEGER PRIMARY KEY AUTOINCREMENT,
        #      Title TEXT,
        #      Poster TEXT,
        #      Description VARCHAR(8192),
        #      Link VARCHAR(1024),
        #      Timestamp INTEGER
        #  )""")

        self.execute("""create table threads (
                    thread_id    integer      unique  not null  primary key  autoincrement,
                    author_id    integer      not null,
                    forum_id     integer      not null,
                    create_time  integer      not null,
                    modify_time  integer      not null,
                    update_time  integer      not null,
                    title        varchar(64)  not null,
                    text         text         not null,
                    score        integer      not null  default 0,
                    hidden       boolean      not null  default false
                    )""")

        self.execute("""create table comments (
                    comment_id   integer      unique  not null  primary key  autoincrement,
                    thread_id    integer      not null,
                    author_id    integer      not null,
                    parent_id    integer,
                    create_time  integer      not null,
                    modify_time  integer      not null,
                    text         text         not null,
                    score        integer      not null  default 0,
                    hidden       boolean      not null  default false
                )""")

        self.execute("""create table forums (
                    forum_id            integer      unique  not null  primary key  autoincrement,
                    name                varchar(64)  not null,
                    description         text         not null  default ''
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

        # #Delete relevant Messages
        # sql_cmd = """
        #      DELETE FROM Messages
        #      WHERE sender='{sender}' OR receiver='{receiver}'
        #      """.format(sender=username, receiver=username)
        # self.execute(sql_cmd)
        # self.commit()

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


    def get_all_resources(self):
        query = """
             SELECT * FROM Resources
         """

        self.execute(query)
        result = self.cur.fetchall()
        return result


    def update_resource(self, resource_id, username, title, description, link):
        query = """
        UPDATE Resources
        SET title = ?, description = ?, link = ?
        WHERE id = ? AND poster = ?
        """
        self.sql_db.execute(query, (title, description, link, resource_id, username))

    def delete_resource(self, resource_id, username):
        query = """
        DELETE FROM Resources
        WHERE id = ? AND poster = ?
        """
        self.sql_db.execute(query, (resource_id, username))

    # -----------------------------------------------------------------------------

    # Check login credentials

    def get_forums(self):
        return self._db().execute('''
            select f.forum_id, name, description, thread_id, title, update_time
            from forums f
            left join threads t
            on t.thread_id = (
              select tt.thread_id
              from threads tt
              where f.forum_id = tt.forum_id and not tt.hidden
              order by update_time desc
              limit 1
            )
            '''
        )

    def get_forum(self, forum_id):
        return self._db().execute('''
            select name, description
            from forums
            where forum_id = ?
            ''',
            (forum_id,)
        ).fetchone()

    def get_threads(self, forum_id, offset, limit, user_id):
        return self._db().execute('''
            select
              t.thread_id,
              title,
              t.create_time,
              t.update_time,
              t.author_id,
              name,
              count(c.thread_id),
              t.hidden
            from
              threads t,
              users
            left join
              comments c
            on
              t.thread_id = c.thread_id
            where forum_id = ?
              and user_id = t.author_id
              and (
                t.hidden = 0 or (
                  select 1 from users
                  where user_id = ?
                    and (
                      user_id = t.author_id
                      -- 1 = moderator, 2 = admin
                      or role in (1, 2)
                    )
                )
              )
            group by t.thread_id
            order by t.update_time desc
            limit ?
            offset ?
            ''',
            (forum_id, user_id, limit, offset)
        )

    def get_thread(self, thread):
        db = self._db()
        title, text, author, author_id, create_time, modify_time, hidden = db.execute('''
            select title, text, name, author_id, create_time, modify_time, hidden
            from threads, users
            where thread_id = ? and author_id = user_id
            ''',
            (thread,)
        ).fetchone()
        comments = db.execute('''
            select
              comment_id,
              parent_id,
              author_id,
              name,
              text,
              create_time,
              modify_time,
              hidden
            from comments
              left join users
              on author_id = user_id
            where thread_id = ?
            ''',
            (thread,)
        )
        return title, text, author, author_id, create_time, modify_time, comments, hidden

    def get_thread_title(self, thread_id):
        return self._db().execute('''
            select title
            from threads
            where thread_id = ?
            ''',
            (thread_id,)
        ).fetchone()

    def get_thread_title_text(self, thread_id):
        return self._db().execute('''
            select title, text
            from threads
            where thread_id = ?
            ''',
            (thread_id,)
        ).fetchone()

    def get_recent_threads(self, limit):
        return self._db().execute('''
            select thread_id, title, modify_date
            from threads
            order by modify_date
            limit ?
            ''',
            (limit,)
        )

    def get_comment(self, comment_id):
        return self._db().execute('''
            select title, c.text
            from comments c, threads t
            where comment_id = ? and c.thread_id = t.thread_id
            ''',
            (comment_id,)
        ).fetchone()

    def get_subcomments(self, comment_id):
        db = self._db()
        thread_id, parent_id, title = db.execute('''
            select threads.thread_id, parent_id, title
            from threads, comments
            where comment_id = ? and threads.thread_id = comments.thread_id
            ''',
            (comment_id,)
        ).fetchone()
        # Recursive CTE, see https://www.sqlite.org/lang_with.html
        return thread_id, parent_id, title, db.execute('''
            with recursive
              descendant_of(id) as (
                select comment_id from comments where comment_id = ?
                union
                select comment_id from descendant_of, comments where id = parent_id
              )
            select
              id,
              parent_id,
              author_id,
              name,
              text,
              create_time,
              modify_time,
              hidden
            from
              descendant_of,
              comments,
              users
            where id = comment_id
              and user_id = author_id
            ''',
            (comment_id,)
        )

    def get_user_password(self, username):
        return self._db().execute('''
            select user_id, password
            from users
            where name = lower(?)
            ''',
            (username,)
        ).fetchone()

    def get_user_password_by_id(self, user_id):
        return self._db().execute('''
            select password
            from users
            where user_id = ?
            ''',
            (user_id,)
        ).fetchone()

    def set_user_password(self, user_id, password):
        return self.change_one('''
            update users
            set password = ?
            where user_id = ?
            ''',
            (password, user_id)
        )

    def get_user_public_info(self, user_id):
        return self._db().execute('''
            select name, about, banned_until
            from users
            where user_id = ?
            ''',
            (user_id,)
        ).fetchone()

    def get_user_private_info(self, user_id):
        return self._db().execute('''
            select about
            from users
            where user_id = ?
            ''',
            (user_id,)
        ).fetchone()

    def set_user_private_info(self, user_id, about):
        db = self._db()
        db.execute('''
            update users
            set about = ?
            where user_id = ?
            ''',
            (about, user_id)
        )
        db.commit()

    def get_user_name_role_banned(self, user_id):
        return self._db().execute('''
            select name, role, banned_until
            from users
            where user_id = ?
            ''',
            (user_id,)
        ).fetchone()

    def get_user_name(self, user_id):
        return self._db().execute('''
            select name
            from users
            where user_id = ?
            ''',
            (user_id,)
        ).fetchone()

    def add_thread(self, author_id, forum_id, title, text, time):
        db = self._db()
        c = db.cursor()
        c.execute('''
            insert into threads (author_id, forum_id, title, text,
                create_time, modify_time, update_time)
            select ?, ?, ?, ?, ?, ?, ?
            from users
            where user_id = ? and banned_until < ?
            ''',
            (author_id, forum_id, title, text, time, time, time, author_id, time)
        )
        rowid = c.lastrowid
        if rowid is None:
            return None
        db.commit()
        return db.execute('''
            select thread_id
            from threads
            where rowid = ?
            ''',
            (rowid,)
        ).fetchone()

    def delete_thread(self, user_id, thread_id):
        db = self._db()
        c = db.cursor()
        c.execute('''
            delete
            from threads
            -- 1 = moderator, 2 = admin
            where thread_id = ? and (
              author_id = ?
              or (select 1 from users where user_id = ? and (role = 1 or role = 2))
            )
            ''',
            (thread_id, user_id, user_id)
        )
        db.commit()
        return c.rowcount > 0

    def delete_comment(self, user_id, comment_id):
        db = self._db()
        c = db.cursor()
        c.execute('''
            delete
            from comments
            where comment_id = ?
              and (
                author_id = ?
                -- 1 = moderator, 2 = admin
                or (select 1 from users where user_id = ? and (role = 1 or role = 2))
              )
              -- Don't allow deleting comments with children
              and (select 1 from comments where parent_id = ?) is null
            ''',
            (comment_id, user_id, user_id, comment_id)
        )
        db.commit()
        return c.rowcount > 0

    def add_comment_to_thread(self, thread_id, author_id, text, time):
        db = self._db()
        c = db.cursor()
        c.execute('''
            insert into comments(thread_id, author_id, text, create_time, modify_time)
            select ?, ?, ?, ?, ?
            from threads, users
            where thread_id = ? and user_id = ? and banned_until < ?
            ''',
            (thread_id, author_id, text, time, time, thread_id, author_id, time)
        )
        if c.rowcount > 0:
            c.execute('''
                update threads
                set update_time = ?
                where thread_id = ?
                ''',
                (time, thread_id)
            )
            db.commit()
            return True
        return False

    def add_comment_to_comment(self, parent_id, author_id, text, time):
        db = self._db()
        c = db.cursor()
        c.execute('''
            insert into comments(thread_id, parent_id, author_id, text, create_time, modify_time)
            select thread_id, ?, ?, ?, ?, ?
            from comments, users
            where comment_id = ? and user_id = ? and banned_until < ?
            ''',
            (parent_id, author_id, text, time, time, parent_id, author_id, time)
        )
        if c.rowcount > 0:
            c.execute('''
                update threads
                set update_time = ?
                where threads.thread_id = (
                  select c.thread_id
                  from comments c
                  where comment_id = ?
                )
                ''',
                (time, parent_id)
            )
            db.commit()
            return True
        return False

    def modify_thread(self, thread_id, user_id, title, text, time):
        db = self._db()
        c = db.cursor()
        c.execute('''
            update threads
            set title = ?, text = ?, modify_time = ?
            where thread_id = ? and (
              (author_id = ? and (select 1 from users where user_id = ? and banned_until < ?))
              -- 1 = moderator, 2 = admin
              or (select 1 from users where user_id = ? and (role = 1 or role = 2))
            )
            ''',
            (
                title, text, time,
                thread_id,
                user_id, user_id, time,
                user_id,
            )
        )
        if c.rowcount > 0:
            db.commit()
            return True
        return False

    def modify_comment(self, comment_id, user_id, text, time):
        db = self._db()
        c = db.cursor()
        c.execute('''
            update comments
            set text = ?, modify_time = ?
            where comment_id = ? and (
              (author_id = ? and (select 1 from users where user_id = ? and banned_until < ?))
              -- 1 = moderator, 2 = admin
              or (select 1 from users where user_id = ? and (role = 1 or role = 2))
            )
            ''',
            (
                text, time,
                comment_id,
                user_id, user_id, time,
                user_id,
            )
        )
        if c.rowcount > 0:
            db.commit()
            return True
        return False



    def set_forum_name(self, forum_id, name):
        return self.change_one('''
            update forums
            set name = ?
            where forum_id = ?
            ''',
            (name, forum_id)
        )

    def set_forum_description(self, forum_id, description):
        return self.change_one('''
            update forums
            set description = ?
            where forum_id = ?
            ''',
            (description, forum_id)
        )

    def add_forum(self, name, description):
        db = self._db()
        db.execute('''
            insert into forums(name, description)
            values (?, ?)
            ''',
            (name, description)
        )
        db.commit()



    def set_config(self, server_name, server_description, registration_enabled):
        return self.change_one('''
            update config
            set name = ?, description = ?, registration_enabled = ?
            ''',
            (server_name, server_description, registration_enabled)
        )

    def set_config_secrets(self, secret_key, captcha_key):
        return self.change_one('''
            update config
            set secret_key = ?, captcha_key = ?
            ''',
            (secret_key, captcha_key)
        )

    def set_user_ban(self, user_id, until):
        return self.change_one('''
            update users
            set banned_until = ?
            where user_id = ?
            ''',
            (until, user_id)
        )

    def set_user_role(self, user_id, role):
        return self.change_one('''
            update users
            set role = ?
            where user_id = ?
            ''',
            (role, user_id)
        )

    def set_thread_hidden(self, thread_id, hide):
        return self.change_one('''
            update threads
            set hidden = ?
            where thread_id = ?
            ''',
            (hide, thread_id)
        )

    def set_comment_hidden(self, comment_id, hide):
        return self.change_one('''
            update comments
            set hidden = ?
            where comment_id = ?
            ''',
            (hide, comment_id)
        )

    def change_one(self, query, values):
        db = self._db()
        c = db.cursor()
        c.execute(query, values)
        if c.rowcount > 0:
            db.commit()
            return True
        return False

    def query(self, q):
        db = self._db()
        c = db.cursor()
        rows = c.execute(q)
        db.commit()
        return rows, c.rowcount

    # def _db(self):
    #     return sqlite3.connect(self.conn, timeout=5)




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
