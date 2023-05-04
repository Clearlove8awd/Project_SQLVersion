'''
    This file will handle our typical Bottle requests and responses 
    You should not have anything beyond basic page loads, handling forms and 
    maybe some simple program logic
'''

from bottle import route, get, post, error, request, static_file, redirect, response, Bottle
import bottle
import model



import bottle
from beaker.middleware import SessionMiddleware

import sql

# Configure the session middleware
session_opts = {
    'session.type': 'file',
    'session.cookie_expires': 300,
    'session.data_dir': './data',
    'session.auto': True
}
app = SessionMiddleware(bottle.app(), session_opts)

user_messages = dict()


#-----------------------------------------------------------------------------
# Static file paths
#-----------------------------------------------------------------------------
curr_user = None
# Allow image loading
@route('/img/<picture:path>')
def serve_pictures(picture):
    '''
        serve_pictures

        Serves images from static/img/

        :: picture :: A path to the requested picture

        Returns a static file object containing the requested picture
    '''
    return static_file(picture, root='static/img/')

#-----------------------------------------------------------------------------

# Allow CSS
@route('/css/<css:path>')
def serve_css(css):
    '''
        serve_css

        Serves css from static/css/

        :: css :: A path to the requested css

        Returns a static file object containing the requested css
    '''
    return static_file(css, root='static/css/')

#-----------------------------------------------------------------------------

# Allow javascript
@route('/js/<js:path>')
def serve_js(js):
    '''
        serve_js

        Serves js from static/js/

        :: js :: A path to the requested javascript

        Returns a static file object containing the requested javascript
    '''
    return static_file(js, root='static/js/')

#-----------------------------------------------------------------------------
# Pages
#-----------------------------------------------------------------------------

# Redirect to login
@get('/')
@get('/home')
def get_index():
    '''
        get_index
        
        Serves the index page
    '''
    return model.index()

#-----------------------------------------------------------------------------

# Display the login page
@get('/login')
def get_login_controller():
    '''
        get_login
        
        Serves the login page
    '''

    return model.login_form()

#-----------------------------------------------------------------------------

# Attempt the login
@post('/login')
def post_login():
    '''
        post_login
        
        Handles login attempts
        Expects a form containing 'username' and 'password' fields
    '''

    # Handle the form processing
    username = request.forms.get('username')
    password = request.forms.get('password')
    session = bottle.request.environ.get('beaker.session')
    session['name'] = username
    session['sender'] = None
    session.save()

    return model.login_check(username, password)



#-----------------------------------------------------------------------------

@get('/about')
def get_about():
    '''
        get_about
        
        Serves the about page
    '''
    return model.about()
#-----------------------------------------------------------------------------


@get('/contact')
def get_contact():
    session = bottle.request.environ.get('beaker.session')
    username = session.get('name')

    return model.contact_friend(username)


@post('/contact')
def add_friend_controller():
    '''
        add_friend_controller

        Handles adding friends
        Expects a form containing 'friend' field
    '''

    friend = request.forms.get('friend')
    session = bottle.request.environ.get('beaker.session')
    username = session.get('name')
    print(username + "--" + friend)
    model.add_friend(username, friend)

    # print the friends list
    # friends = model.get_friends(curr_user)

    return redirect('/contact')


@route('/chat')
def chat():
    session = bottle.request.environ.get('beaker.session')
    username = session.get('name')
    user_to = request.forms.get('receiver')  # Get the other user from the query parameter
    # sender = request.forms.get('sender')
    #
    # if session['sender'] is None or session['sender'] != sender:
    #     session['sender'] = sender
    if username is not None:
        # print(session['sender'])
        if session['sender']:
            print("Got sender", session['sender'])
            messages = model.get_message(username, session['sender'])
            messages = messages.replace("\n", "<br>")
            return model.page_view("chat", username=username, friend=model.get_friends(username),
                                   chat_messages=messages)
        else:
            return model.page_view("chat", username=username, friend=model.get_friends(username),
                                   chat_messages="No message available")
    else:
        return model.not_logged_in()



import traceback,time
@post('/chat')
def post_chat():

    session = bottle.request.environ.get('beaker.session')
    username = session.get('name')
    user_to = request.forms.get('receiver')
    message = request.forms.get('message')

    sender = request.forms.get('sender')
    if sender:
        if session['sender'] is None or session['sender'] != sender:
            session['sender'] = sender
    print(username, user_to, message, session['sender'])

    try:
        # Check if the "Send" button was clicked
        if username and user_to and message:
            print("Sending message")
            timestamp = int(time.time())
            print(timestamp)
            model.send_message(username, user_to, message, timestamp)
    except Exception:
        print(traceback.format_exc())

@get('/register')
def get_register():
    '''
        get_register
        Serves the registration page
    '''
    return model.register_form()  # change this line

@post('/register')
def register():
    username = request.forms.get('username')
    password = request.forms.get('password')
    model.register_user(username, password)

    database_args = "UserDatabase.db"
    sql_db = sql.SQLDatabase(database_args)
    user = sql_db.get_user(username)

    if user != None:
        print(f"User {username} has been successfully registered!")
    else:
        print(f"User registration failed for {username}!")

    return redirect('/login')


# Help with debugging
@post('/debug/<cmd:path>')
def post_debug(cmd):
    return model.debug(cmd)

#-----------------------------------------------------------------------------

# 404 errors, use the same trick for other types of errors
@error(404)
def error(error): 
    return model.handle_errors(error)


@route('/logout')
def logout():
    session = bottle.request.environ.get('beaker.session')
    if 'name' in session:
        del session['name']
    session.save()
    return redirect("home")


