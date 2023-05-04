'''
    Our Model class
    This should control the actual "logic" of your website
    And nicely abstracts away the program logic from your page loading
    It should exist as a separate layer to any database or data structure that you might be using
    Nothing here should be stateful, if it's stateful let the database handle it
'''
import os
import traceback
import uuid

import sql
import view
import random
from no_sql_db import database
import bcrypt
from bottle import response
import bottle
import rsa
import datetime, time

# Initialise our views, all arguments are defaults for the template
page_view = view.View()


# -----------------------------------------------------------------------------
# Index
# -----------------------------------------------------------------------------

def index():
    '''
        index
        Returns the view for the index
    '''
    return page_view("index")


# -----------------------------------------------------------------------------
# Login
# -----------------------------------------------------------------------------

def login_form():
    '''
        login_form
        Returns the view for the login_form
    '''
    return page_view("login")


# -----------------------------------------------------------------------------
# Add a new route to serve the chat page


def contact_friend(user):
    '''
        chat
        Returns the view for the chat page
    '''
    # Get the user's friend list from database
    friends = get_friends(user)
    # Get the user's username from the cookie
    return page_view("contact", username=user, friend=friends)


# Add friend to user's friend list in database
'''
def add_friend(username, friend):
    
        add_friend
        Adds a friend to the user's friend list

        :: username :: The username
        :: friend :: The friend to add
    
    user = database.search_table('users', 'username', username)
    friend_search = database.search_table('users', 'username', friend)
    print(user, friend_search)
    if user and friend_search:
        # if user[3] do not exist friend, append friend to user[3]
        if friend_search[1] not in user[3]:
            user[3].append(friend_search[1])
        if user[1] not in friend_search[3]:
            friend_search[3].append(user[1])
    return
'''
def add_friend(username, friend):
    '''
        add_friend
        Adds a friend to the user's friend list

        :: username :: The username
        :: friend :: The friend to add
    '''
    database_args = "UserDatabase.db"
    sql_db = sql.SQLDatabase(database_args)

    user_row = sql_db.get_user(username)
    if user_row == None:
        return None
    friend_row = sql_db.get_user(friend)
    if friend_row == None:
        return None

    id_1 = user_row[0]
    id_2 = friend_row[0]
    if id_1==id_2:
        print("You cannot add yourself to friend")
        return None
    elif id_1>id_2:
        tem = id_1
        id_1 = id_2
        id_2 = tem

    if sql_db.get_targetfriend(id_1,id_2)!=None:
        print("The friend has been in the friend list")
        return
    sql_db.add_friend(id_1,id_2)
        



    user = database.search_table('users', 'username', username)
    friend_search = database.search_table('users', 'username', friend)
    print(user, friend_search)
    if user and friend_search:
        # if user[3] do not exist friend, append friend to user[3]
        if friend_search[1] not in user[3]:
            user[3].append(friend_search[1])
        if user[1] not in friend_search[3]:
            friend_search[3].append(user[1])
    return

# Get user's friend list from database
def get_friends(username):
    '''
        get_friends
        Gets the user's friend list

        :: username :: The username

        Returns a list of friends
    '''

    '''
    friends = ""
    # get the friends from the database
    user = database.search_table('users', 'username', username)
    if user:
        # list out the friends from user[3] one by one
        for friend in user[3]:
            # if friends is not empty, append the friend to friends
            if friends:
                friends = friends + "," + friend
            else:
                friends = friend
    # print(friends)
    return friends
    '''

    friends = ""
    database_args = "UserDatabase.db"
    sql_db = sql.SQLDatabase(database_args)
    result = sql_db.get_user(username)
    if result== None:
        print("No such user")
        return friends
    id = result[0]
    friend_list = sql_db.get_friends(id)
    if friend_list==None:
        return friends
    if friend_list == []:
        return friends
    count=0
    for row in friend_list:
        if (row[0] == id):
            friend_id = row[1]
        else:
            friend_id = row[0]
        user_row = sql_db.get_user_by_id(friend_id)
        if count == 0:
            friends = friends + user_row[1]
        else:
            friends = friends + "," + user_row[1]
        count+=1
    return friends






'''

def login_check(username, password):
    users = database.search_table('users', 'username', username)
    if users:
        hashed_password = users[2]

        if bcrypt.checkpw(password.encode('utf-8'), hashed_password):
            response.set_cookie("username", username)
            return page_view("valid", name=username)
        else:
            return page_view("invalid", reason="Wrong password")
    else:
        return page_view("invalid", reason="User does not exist")

'''
def login_check(username, password):
    database_args = "UserDatabase.db"
    sql_db = sql.SQLDatabase(database_args)

    row = sql_db.get_user(username)

    if row != None:
        hashed_password = bytes.fromhex(row[2])

        if bcrypt.checkpw(password.encode('utf-8'), hashed_password):
            response.set_cookie("username", username)
            return page_view("valid", name=username)
        else:
            return page_view("invalid", reason="Wrong password")
    else:
        return page_view("invalid", reason="User does not exist")

# -----------------------------------------------------------------------------
# About
# -----------------------------------------------------------------------------

def about():
    '''
        about
        Returns the view for the about page
    '''
    return page_view("about", garble=about_garble())


def register_user(username, password):
    # Check if the username already exists

    database_args = "UserDatabase.db"
    sql_db = sql.SQLDatabase(database_args)
    row = sql_db.get_user(username)

    if row != None:
        return page_view("register", error="Username already exists")

    # Hash and salt the password
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)

    # Generate the public and private keys
    publicKey, privateKey = generate_keys()

    # Add the user to the database with their public and private keys
    #database.create_table_entry('users', [user_id, username, hashed_password, [], publicKey, privateKey])
    sql_db.add_user(username, hashed_password, publicKey, privateKey)

    #print(database.search_table("users", "username", username))

    # Redirect the user to the login page with a success message
    return page_view("login", message="Registration successful. Please log in.")


def register_form():
    '''
        register_form
        Returns the view for the registration form
    '''
    return page_view("register")

'''
def get_user(username):
    database_args = "UserDatabase.db"
    sql_db = sql.SQLDatabase(database_args)
    user = sql_db.get_user(username)
    return user
    '''


# -----------------------------------------------------------------------------
# Chat
# -----------------------------------------------------------------------------


def send_message(username, user_to, message, timestamp):

    database_args = "UserDatabase.db"
    sql_db = sql.SQLDatabase(database_args)

    '''
    if not database.search_table('users', 'username', user_to):
        return page_view("chat", error_msg="Receiver does not exist", chat_messages="b")
    if user_to not in database.search_table("users", "username", username)[3]:
        # Return an error message if the receiver is not a friend
        return page_view("chat", error_msg="You are not friends with this user.", chat_messages="c")
        '''
    curuser_row = sql_db.get_user(username)
    user_to_row = sql_db.get_user(user_to)

    if curuser_row == None:
        print("Sender does not exist")
        return
    if user_to_row == None:
        print("Receiver does not exist")
        return page_view("chat", error_msg="Receiver does not exist", chat_messages="b")
    if sql_db.get_targetfriend(curuser_row[0], user_to_row[0]) == None:
        # Return an error message if the receiver is not a friend
        #print(type(curuser_row[0]))
        print("You are not friends with this user.")
        return page_view("chat", error_msg="You are not friends with this user.", chat_messages="c")


    '''
    # Get the user's public and private keys
    sender_public_key = database.search_table("users", "username", username)[4]
    sender_private_key = database.search_table("users", "username", username)[5]
    # Get the receiver's public and private keys
    receiver_public_key = database.search_table("users", "username", user_to)[4]
    receiver_private_key = database.search_table("users", "username", user_to)[5]
    '''

    sender_public_key = sql_db.search_table("Users", "username", username)[3]
    sender_private_key = sql_db.search_table("Users", "username", username)[4]
    receiver_public_key = sql_db.search_table("Users", "username", user_to)[3]
    receiver_private_key = sql_db.search_table("Users", "username", user_to)[4]

    # Get the messages between the two users
    #message_id = len(database.tables['messages'].entries) + 1

    signature = create_signature(message, sender_private_key)
    encoded_message = encrypt_message(message, receiver_public_key)
    encoded_message_hex = encoded_message.hex()

    '''
    if database.search_table("messages", "sender", username):
        database.search_table("messages", "sender", username)[3].append([encoded_message, signature, timestamp])
    else:
        database.create_table_entry('messages',
                                    [message_id, username, user_to, [[encoded_message, signature, timestamp]]])
    print(database.search_table("messages", "sender", username), database.search_table("messages", "sender", user_to))
    '''

    sql_db.add_message(username, user_to, encoded_message_hex, signature, timestamp)
    #sql_db.conn.close()


def get_message(current_user, receiver):
    '''
    print(database.search_table("messages", "sender", username),
          database.search_table("messages", "sender", user_to))
    messages_from_sender = database.search_table("messages", "sender", username)[3]
    '''
    database_args = "UserDatabase.db"
    sql_db = sql.SQLDatabase(database_args)
    messages_from_receiver = sql_db.get_allmessages(receiver, current_user)
    if messages_from_receiver is None:
        messages_from_receiver = []

    messages_from_current_user = sql_db.get_allmessages(current_user, receiver)
    if messages_from_current_user is None:
        messages_from_current_user = []

    print(messages_from_receiver)
    print(messages_from_current_user)

    '''
    # Get the user's public and private keys
    sender_public_key = database.search_table("users", "username", username)[4]
    sender_private_key = database.search_table("users", "username", username)[5]

    # Get the receiver's public and private keys
    receiver_public_key = database.search_table("users", "username", user_to)[4]
    receiver_private_key = database.search_table("users", "username", user_to)[5]
'''
    sender_public_key = sql_db.search_table("Users", "username", current_user)[3]
    sender_private_key = sql_db.search_table("Users", "username", current_user)[4]
    receiver_public_key = sql_db.search_table("Users", "username", receiver)[3]
    receiver_private_key = sql_db.search_table("Users", "username", receiver)[4]


    all_messages = []
    #sql_db.conn.close()


    for message in messages_from_receiver:
        encoded_message = bytes.fromhex(message[3])
        decoded_message = decrypt_message(encoded_message, sender_private_key)
        if not verify_signature(decoded_message, message[4], receiver_public_key):
            print("Signature verification failed")
            return page_view("chat", chat_messages="Signature verification failed")
        print("Signature verification successful")

        all_messages.append([decoded_message, message[5], message[1], message[2]])
        #database.search_table("messages", "sender", username)[1],
        #database.search_table("messages", "sender", username)[2]]

    for message in messages_from_current_user:
        encoded_message = bytes.fromhex(message[3])
        decoded_message = decrypt_message(encoded_message, receiver_private_key)
        if not verify_signature(decoded_message, message[4], sender_public_key):
            print("Signature verification failed")
            return page_view("chat", chat_messages="Signature verification failed")
        print("Signature verification successful")
        all_messages.append([decoded_message, message[5], message[1], message[2]])
        #database.search_table("messages", "sender", user_to)[1],
        #database.search_table("messages", "sender", user_to)[2]]

    print(all_messages)

    sorted_messages = sorted(all_messages, key=lambda x: x[1])
    for i, message in enumerate(sorted_messages):
        sorted_messages[i][1] = datetime.datetime.fromtimestamp(sorted_messages[i][1]).strftime('%Y-%m-%d %H:%M:%S %Z')
    # print(sorted_messages)
    result = ""
    for message in sorted_messages:
        result += f"{message[1]} -- From {message[2]} to {message[3]}: {message[0]}\n"
    # print(result)
    return result


# Returns a random string each time
def about_garble():
    '''
        about_garble
        Returns one of several strings for the about page
    '''
    garble = ["leverage agile frameworks to provide a robust synopsis for high level overviews.",
              "iterate approaches to corporate strategy and foster collaborative thinking to further the overall value proposition.",
              "organically grow the holistic world view of disruptive innovation via workplace change management and empowerment.",
              "bring to the table win-win survival strategies to ensure proactive and progressive competitive domination.",
              "ensure the end of the day advancement, a new normal that has evolved from epistemic management approaches and is on the runway towards a streamlined cloud solution.",
              "provide user generated content in real-time will have multiple touchpoints for offshoring."]
    return garble[random.randint(0, len(garble) - 1)]


# -----------------------------------------------------------------------------
# Debug
# -----------------------------------------------------------------------------

def debug(cmd):
    try:
        return str(eval(cmd))
    except:
        pass


# -----------------------------------------------------------------------------
# Not logged in
# -----------------------------------------------------------------------------

def not_logged_in():
    return page_view("not_logged_in")


# -----------------------------------------------------------------------------
# User already logged in
# -----------------------------------------------------------------------------

def user_already_logged_in():
    return page_view("already_logged_in")


# -----------------------------------------------------------------------------
# 404
# Custom 404 error page
# -----------------------------------------------------------------------------

def handle_errors(error):
    error_type = error.status_line
    error_msg = error.body
    return page_view("error", error_type=error_type, error_msg=error_msg)


# Add this function for generating keys
def generate_keys():
    publicKey, privateKey = rsa.newkeys(512)
    return publicKey.save_pkcs1().decode(), privateKey.save_pkcs1().decode()


# Add this function for getting user key
def get_user_key(username):
    user = database.search_table('users', 'username', username)
    if user:
        return user[4]
    return None


def get_messages_between_users(user1, user2):
    messages = []
    for message in database.tables['messages'].entries:
        if (message[1] == user1 and message[2] == user2) or (message[1] == user2 and message[2] == user1):
            messages.append(message)
    return messages


def encrypt_message(message, public_key_pem):
    public_key = rsa.PublicKey.load_pkcs1(public_key_pem.encode())
    ciphertext = rsa.encrypt(message.encode(), public_key)
    return ciphertext


def decrypt_message(ciphertext, private_key_pem):
    private_key = rsa.PrivateKey.load_pkcs1(private_key_pem.encode())
    plaintext = rsa.decrypt(ciphertext, private_key)
    return plaintext.decode()


def get_public_key(username):
    user_data = database.search_table('users', 'username', username)
    if user_data:
        return user_data[4]
    return None


def create_signature(message, private_key_str):
    private_key = rsa.PrivateKey.load_pkcs1(private_key_str.encode())
    message_hash = rsa.compute_hash(message.encode('utf-8'), 'SHA-256')
    signature = rsa.sign_hash(message_hash, private_key, 'SHA-256')
    return signature.hex()


def verify_signature(message, signature, public_key_pem):
    public_key = rsa.PublicKey.load_pkcs1(public_key_pem.encode())
    message_hash = rsa.compute_hash(message.encode('utf-8'), 'SHA-256')
    try:
        rsa.verify(message.encode('utf-8'), bytes.fromhex(signature), public_key)
        return True
    except rsa.VerificationError:
        return False
