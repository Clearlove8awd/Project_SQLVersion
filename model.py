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
def add_friend(username, friend):
    '''
        add_friend
        Adds a friend to the user's friend list

        :: username :: The username
        :: friend :: The friend to add
    '''
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
    if database.search_table('users', 'username', username):
        return page_view("register", error="Username already exists")

    # Hash and salt the password
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)

    # Generate the public and private keys
    publicKey, privateKey = generate_keys()
    user_id = len(database.tables['users'].entries) + 1

    # Add the user to the database with their public and private keys
    database.create_table_entry('users', [user_id, username, hashed_password, [], publicKey, privateKey])

    print(database.search_table("users", "username", username))

    # Redirect the user to the login page with a success message
    return page_view("login", message="Registration successful. Please log in.")


def register_form():
    '''
        register_form
        Returns the view for the registration form
    '''
    return page_view("register")


def get_user(username):
    user = database.get_user('users', username)
    return user


# -----------------------------------------------------------------------------
# Chat
# -----------------------------------------------------------------------------


def send_message(username, user_to, message, timestamp):
    if not database.search_table('users', 'username', user_to):
        return page_view("chat", error_msg="Receiver does not exist", chat_messages="b")
    if user_to not in database.search_table("users", "username", username)[3]:
        # Return an error message if the receiver is not a friend
        return page_view("chat", error_msg="You are not friends with this user.", chat_messages="c")

    # Get the user's public and private keys
    sender_public_key = database.search_table("users", "username", username)[4]
    sender_private_key = database.search_table("users", "username", username)[5]
    # Get the receiver's public and private keys
    receiver_public_key = database.search_table("users", "username", user_to)[4]
    receiver_private_key = database.search_table("users", "username", user_to)[5]

    # Get the messages between the two users

    message_id = len(database.tables['messages'].entries) + 1

    signature = create_signature(message, sender_private_key)
    encoded_message = encrypt_message(message, receiver_public_key)

    if database.search_table("messages", "sender", username):
        database.search_table("messages", "sender", username)[3].append([encoded_message, signature, timestamp])
    else:
        database.create_table_entry('messages',
                                    [message_id, username, user_to, [[encoded_message, signature, timestamp]]])
    print(database.search_table("messages", "sender", username), database.search_table("messages", "sender", user_to))


def get_message(username, user_to):
    try:
        # print(username, user_to)
        print(database.search_table("messages", "sender", username),
              database.search_table("messages", "sender", user_to))
        messages_from_sender = database.search_table("messages", "sender", username)[3]
        # signature_from_sendermessage = database.search_table("messages", "sender", username)[3][1]
    except Exception:
        messages_from_sender = []
        signature_from_sendermessage = None
        pass

    try:
        messages_from_curuser = database.search_table("messages", "sender", user_to)[3]
        # signature_from_curuser = database.search_table("messages", "sender", user_to)[3][1]
    except Exception:
        messages_from_curuser = []
        signature_from_curuser = None

    print(messages_from_sender)
    print(messages_from_curuser)
    # Get the user's public and private keys
    sender_public_key = database.search_table("users", "username", username)[4]
    sender_private_key = database.search_table("users", "username", username)[5]

    # Get the receiver's public and private keys
    receiver_public_key = database.search_table("users", "username", user_to)[4]
    receiver_private_key = database.search_table("users", "username", user_to)[5]

    all_messages = []

    if messages_from_sender:
        for message in messages_from_sender:

            # print(message)
            decoded_message = decrypt_message(message[0], receiver_private_key)
            # print(decoded_message)
            if not verify_signature(decoded_message, message[1], sender_public_key):
                print("Signature verification failed")
                return page_view("chat", chat_messages="Signature verification failed")
            print("Signature verification successful")
            all_messages.append([decoded_message, message[2],
                                 database.search_table("messages", "sender", username)[1],
                                 database.search_table("messages", "sender", username)[2]])
    if messages_from_curuser:
        for message in messages_from_curuser:

            print(message)
            decoded_message = decrypt_message(message[0], sender_private_key)
            print(decoded_message)
            if not verify_signature(decoded_message, message[1], receiver_public_key):
                print("Signature verification failed")
                return page_view("chat", chat_messages="Signature verification failed")
            print("Signature verification successful")
            all_messages.append([decoded_message, message[2],
                                 database.search_table("messages", "sender", user_to)[1],
                                 database.search_table("messages", "sender", user_to)[2]])
    # print(all_messages)
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
