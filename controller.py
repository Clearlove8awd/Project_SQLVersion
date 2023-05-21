'''
    This file will handle our typical Bottle requests and responses 
    You should not have anything beyond basic page loads, handling forms and 
    maybe some simple program logic
'''

from bottle import route, get, post, error, request, static_file, redirect, response, Bottle, template
import bottle
import datetime
import model
import sqlite3

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
database_args = "UserDatabase.sql_db"
sql_db = sql.SQLDatabase(database_args)
THREADS_PER_PAGE = 50
#-----------------------------------------------------------------------------
# Static file paths
#-----------------------------------------------------------------------------
# curr_user = None
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

    database_args = "UserDatabase.sql_db"
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



@app.route('/forum/<int:forum_id>/')
def forum(forum_id):
    title, description = sql_db.get_forum(forum_id)
    offset = int(request.args.get('p', 0))
    session = bottle.request.environ.get('beaker.session')
    user_id = session.get('user_id', -1)
    threads = [*sql_db.get_threads(forum_id, offset, THREADS_PER_PAGE + 1, user_id)]
    if len(threads) == THREADS_PER_PAGE + 1:
        threads.pop()
        next_page = offset + THREADS_PER_PAGE
    else:
        next_page = None
    return template(
        'forum.html',
        title = title,
        user = get_user(),
        #  
        forum_id = forum_id,
        description = description,
        threads = threads,
        next_page = next_page,
        prev_page = max(offset - THREADS_PER_PAGE, 0) if offset > 0 else None,
    )

@app.route('/thread/<int:thread_id>/')
def thread(thread_id):
    user = get_user()
    title, text, author, author_id, create_time, modify_time, comments, hidden = sql_db.get_thread(thread_id)
    comments = create_comment_tree(comments, user)
    return template(
        'thread.html',
        title = title,
         
        user = user,
        text = text,
        author = author,
        author_id = author_id,
        thread_id = thread_id,
        hidden = hidden,
        create_time = create_time,
        modify_time = modify_time,
        comments = comments,
    )

@app.route('/comment/<int:comment_id>/')
def comment(comment_id):
    user = get_user()
    thread_id, parent_id, title, comments = sql_db.get_subcomments(comment_id)
    comments = create_comment_tree(comments, user)
    reply_comment, = comments
    comments = reply_comment.children
    reply_comment.children = []
    return template(
        'comments.html',
        title = title,
         
        user = user,
        reply_comment = reply_comment,
        comments = comments,
        parent_id = parent_id,
        thread_id = thread_id,
    )

# @app.route('/login/', methods = ['GET', 'POST'])
# def login():
#     if request.method == 'POST':
#         v = sql_db.get_user_password(request.form['username'])
#         if v is not None:
#             id, hash = v
#             if password.verify(request.form['password'], hash):
#                 flash('Logged in', 'success')
#                 session['user_id'] = id
#                 session.permanent = True
#                 return redirect(url_for('index'))
#         else:
#             # Sleep to reduce effectiveness of bruteforce
#             time.sleep(0.1)
#         flash('Username or password is invalid', 'error')
#     return template(
#         'login.html',
#         title = 'Login',
#
#         user = get_user()
#     )
#
# @app.route('/logout/')
# def logout():
#     session.pop('user_id')
#     return redirect(url_for('index'))

@app.route('/user/', methods = ['GET', 'POST'])
def user_edit():
    user = get_user()
    if user is None:
        return redirect('login')

    if request.method == 'POST':
        about = trim_text(request.form['about'])
        sql_db.set_user_private_info(user.id, about)
        flash('Updated profile', 'success')
        request.session['flash_message']
    else:
        about, = sql_db.get_user_private_info(user.id)

    return template(
        'user_edit.html',
        title = 'Edit profile',

        user = user,
        about = about
    )

@app.route('/user/edit/password/', methods = ['POST'])
def user_edit_password():
    user_id = session.get('user_id')
    if user_id is None:
        return redirect('login')

    new = request.form['new']
    if len(new) < 8:
        flash('New password must be at least 8 characters long', 'error')
    else:
        hash, = sql_db.get_user_password_by_id(user_id)
        if password.verify(request.form['old'], hash):
            if sql_db.set_user_password(user_id, password.hash(new)):
                flash('Updated password', 'success')
            else:
                flash('Failed to update password', 'error')
        else:
            flash('Old password does not match', 'error')
    return redirect('user_edit')

@app.route('/user/<int:user_id>/')
def user_info(user_id):
    name, about, banned_until = sql_db.get_user_public_info(user_id)
    return template(
        'user_info.html',
        title = 'Profile',

        user = get_user(),
        name = name,
        id = user_id,
        banned_until = banned_until,
        about = about
    )

@app.route('/forum/<int:forum_id>/new/', methods = ['GET', 'POST'])
def new_thread(forum_id):
    user_id = session.get('user_id')
    if user_id is None and not config.registration_enabled:
        # Can't create a thread without an account
        return redirect('login')

    if request.method == 'POST':
        if user_id is None:
            # Attempt to create a user account first
            if register_user(True):
                user_id = session['user_id']

        if user_id is not None:
            title, text = request.form['title'].strip(), trim_text(request.form['text'])
            title = title.strip()
            if title == '' or text == '':
                flash('Title and text may not be empty', 'error')
                return redirect('forum', forum_id = forum_id)
            id = sql_db.add_thread(user_id, forum_id, title, text, time.time_ns())
            if id is None:
                flash('Failed to create thread', 'error')
                return redirect('forum', forum_id = forum_id)
            else:
                id, = id
                flash('Created thread', 'success')
                return redirect('thread', thread_id = id)

    return template(
        'new_thread.html',
        title = 'Create new thread',

        user = get_user(),
    )

@app.route('/thread/<int:thread_id>/confirm_delete/')
def confirm_delete_thread(thread_id):
    title, = sql_db.get_thread_title(thread_id)
    return template(
        'confirm_delete_thread.html',
        title = 'Delete thread',

        user = get_user(),
        thread_title = title,
    )

@app.route('/thread/<int:thread_id>/delete/', methods = ['POST'])
def delete_thread(thread_id):
    user_id = session.get('user_id')
    if user_id is None:
        return redirect('login')

    if sql_db.delete_thread(user_id, thread_id):
        flash('Thread has been deleted', 'success')
    else:
        flash('Thread could not be removed', 'error')
        # TODO return 403, maybe?
    return redirect('index')

def _add_comment_check_user():
    user_id = session.get('user_id')
    if user_id is not None:
        return user_id
    # if not config.registration_enabled:
    #     flash('Registrations are not enabled. Please log in to comment', 'error')
    if register_user(True):
        return session['user_id']

@app.route('/thread/<int:thread_id>/comment/', methods = ['POST'])
def add_comment(thread_id):
    user_id = _add_comment_check_user()
    if user_id is not None:
        text = trim_text(request.form['text'])
        if text == '':
            flash('Text may not be empty', 'error')
        elif sql_db.add_comment_to_thread(thread_id, user_id, text, time.time_ns()):
            flash('Added comment', 'success')
        else:
            flash('Failed to add comment', 'error')
    return redirect(url_for('thread', thread_id = thread_id))

@app.route('/comment/<int:comment_id>/comment/', methods = ['POST'])
def add_comment_parent(comment_id):
    user_id = _add_comment_check_user()
    if user_id is not None:
        text = trim_text(request.form['text'])
        if text == '':
            flash('Text may not be empty', 'error')
        elif sql_db.add_comment_to_comment(comment_id, user_id, text, time.time_ns()):
            flash('Added comment', 'success')
        else:
            flash('Failed to add comment', 'error')
    return redirect(url_for('comment', comment_id = comment_id))

@app.route('/comment/<int:comment_id>/confirm_delete/')
def confirm_delete_comment(comment_id):
    title, text = sql_db.get_comment(comment_id)
    return template(
        'confirm_delete_comment.html',
        title = 'Delete comment',

        user = get_user(),
        thread_title = title,
        text = text,
    )

@app.route('/comment/<int:comment_id>/delete/', methods = ['POST'])
def delete_comment(comment_id):
    user_id = session.get('user_id')
    if user_id is None:
        return redirect(url_for('login'))

    if sql_db.delete_comment(user_id, comment_id):
        flash('Comment has been deleted', 'success')
    else:
        flash('Comment could not be removed', 'error')
        # TODO return 403, maybe?
    return redirect(url_for('index'))

@app.route('/thread/<int:thread_id>/edit/', methods = ['GET', 'POST'])
def edit_thread(thread_id):
    user_id = session.get('user_id')
    if user_id is None:
        return redirect(url_for('login'))

    if request.method == 'POST':
        title, text = request.form['title'].strip(), trim_text(request.form['text'])
        if title == '' or text == '':
            flash('Title and text may not be empty', 'error')
        elif sql_db.modify_thread(
            thread_id,
            user_id,
            title,
            text,
            time.time_ns(),
        ):
            flash('Thread has been edited', 'success')
        else:
            flash('Thread could not be edited', 'error')
        return redirect(url_for('thread', thread_id = thread_id))

    title, text = sql_db.get_thread_title_text(thread_id)

    return template(
        'edit_thread.html',
        title = 'Edit thread',

        user = get_user(),
        thread_title = title,
        text = text,
    )

@app.route('/comment/<int:comment_id>/edit/', methods = ['GET', 'POST'])
def edit_comment(comment_id):
    user_id = session.get('user_id')
    if user_id is None:
        return redirect(url_for('login'))

    if request.method == 'POST':
        text = trim_text(request.form['text'])
        if text == '':
            flash('Text may not be empty', 'error')
        elif sql_db.modify_comment(
            comment_id,
            user_id,
            trim_text(request.form['text']),
            time.time_ns(),
        ):
            flash('Comment has been edited', 'success')
        else:
            flash('Comment could not be edited', 'error')
        return redirect(url_for('comment', comment_id = comment_id))

    title, text = sql_db.get_comment(comment_id)

    return template(
        'edit_comment.html',
        title = 'Edit comment',

        user = get_user(),
        thread_title = title,
        text = text,
    )


@app.route('/admin/')
def admin():
    chk, user = _admin_check()
    if not chk:
        return user

    return template(
        'admin/index.html',
        title = 'Admin panel',

        forums = sql_db.get_forums(),
        users = sql_db.get_users(),
    )

@app.route('/admin/query/', methods = ['GET', 'POST'])
def admin_query():
    chk, user = _admin_check()
    if not chk:
        return user

    try:
        rows, rowcount = sql_db.query(request.form['q']) if request.method == 'POST' else []
        if rowcount > 0:
            flash(f'{rowcount} rows changed', 'success')
    except Exception as e:
        flash(e, 'error')
        rows = []
    return template(
        'admin/query.html',
        title = 'Query',

        rows = rows,
    )

@app.route('/admin/forum/<int:forum_id>/edit/<string:what>/', methods = ['POST'])
def admin_edit_forum(forum_id, what):
    chk, user = _admin_check()
    if not chk:
        return user

    try:
        if what == 'description':
            res = sql_db.set_forum_description(forum_id, trim_text(request.form['description']))
        elif what == 'name':
            res = sql_db.set_forum_name(forum_id, request.form['name'])
        else:
            flash(f'Unknown property "{what}"', 'error')
            res = None
        if res is True:
            flash(f'Updated {what}', 'success')
        elif res is False:
            flash(f'Failed to update {what}', 'error')
    except Exception as e:
        flash(e, 'error')
    return redirect(url_for('admin'))

@app.route('/admin/forum/new/', methods = ['POST'])
def admin_new_forum():
    chk, user = _admin_check()
    if not chk:
        return user

    try:
        sql_db.add_forum(request.form['name'], trim_text(request.form['description']))
        flash('Added forum', 'success')
    except Exception as e:
        flash(str(e), 'error')
    return redirect(url_for('admin'))

@app.route('/admin/config/edit/', methods = ['POST'])
def admin_edit_config():
    chk, user = _admin_check()
    if not chk:
        return user

    try:
        sql_db.set_config(
            request.form['server_name'],
            trim_text(request.form['server_description']),
            'registration_enabled' in request.form,
        )
        flash('Updated config. Refresh the page to see the changes.', 'success')
        restart()
    except Exception as e:
        flash(str(e), 'error')
    return redirect(url_for('admin'))

@app.route('/admin/config/new_secrets/', methods = ['POST'])
def admin_new_secrets():
    chk, user = _admin_check()
    if not chk:
        return user

    secret_key = secrets.token_urlsafe(30)
    captcha_key = secrets.token_urlsafe(30)
    try:
        sql_db.set_config_secrets(secret_key, captcha_key)
        flash('Changed secrets. You will be logged out.', 'success')
        restart()
    except Exception as e:
        flash(str(e), 'error')
    return redirect(url_for('admin'))


def ban_user(user_id):
    chk, user = _moderator_check()
    if not chk:
        return user

    d, t = request.form['days'], request.form['time']
    d = 0 if d == '' else int(d)
    h, m = (0, 0) if t == '' else map(int, t.split(':'))
    until = time.time_ns() + (d * 24 * 60 + h * 60 + m) * (60 * 10**9)
    until = min(until, 0x7fff_ffff_ffff_ffff)

    try:
        if sql_db.set_user_ban(user_id, until):
            flash('Banned user', 'success')
        else:
            flash('Failed to ban user', 'error')
    except Exception as e:
        flash(str(e), 'error')

@app.route('/user/<int:user_id>/ban/', methods = ['POST'])
def moderator_ban_user(user_id):
    return ban_user(user_id) or redirect(url_for('user_info', user_id = user_id))

@app.route('/admin/user/<int:user_id>/ban/', methods = ['POST'])
def admin_ban_user(user_id):
    return ban_user(user_id) or redirect(url_for('admin'))

def unban_user(user_id):
    chk, user = _moderator_check()
    if not chk:
        return user

    try:
        if sql_db.set_user_ban(user_id, 0):
            flash('Unbanned user', 'success')
        else:
            flash('Failed to unban user', 'error')
    except Exception as e:
        flash(str(e), 'error')

@app.route('/user/<int:user_id>/unban/', methods = ['POST'])
def moderator_unban_user(user_id):
    return unban_user(user_id) or redirect(url_for('user_info', user_id = user_id))

@app.route('/admin/user/<int:user_id>/unban/', methods = ['POST'])
def admin_unban_user(user_id):
    return unban_user(user_id) or redirect(url_for('admin'))

@app.route('/admin/user/new/', methods = ['POST'])
def admin_new_user():
    chk, user = _admin_check()
    if not chk:
        return user

    try:
        name, passwd = request.form['name'], request.form['password']
        if name == '' or passwd == '':
            flash('Name and password may not be empty')
        elif sql_db.add_user(name, password.hash(passwd), time.time_ns()):
            flash('Added user', 'success')
        else:
            flash('Failed to add user', 'error')
    except Exception as e:
        flash(str(e), 'error')
    return redirect(url_for('admin'))

@app.route('/admin/user/<int:user_id>/edit/role/', methods = ['POST'])
def admin_set_role(user_id):
    chk, user = _admin_check()
    if not chk:
        return user

    try:
        role = request.form['role']
        if role not in ('0', '1', '2'):
            flash(f'Invalid role type ({role})', 'error')
        else:
            sql_db.set_user_role(user_id, role)
            flash('Set user role', 'success')
    except Exception as e:
        flash(str(e), 'error')
    return redirect(url_for('admin'))

@app.route('/admin/restart/', methods = ['POST'])
def admin_restart():
    chk, user = _admin_check()
    if not chk:
        return user

    restart()
    return redirect(url_for('admin'))

@app.route('/thread/<int:thread_id>/hide/', methods = ['POST'])
def set_hide_thread(thread_id):
    chk, user = _moderator_check()
    if not chk:
        return user

    try:
        hide = request.form['hide'] != '0'
        hide_str = 'Hidden' if hide else 'Unhidden'
        if sql_db.set_thread_hidden(thread_id, hide):
            flash(f'{hide_str} thread', 'success')
        else:
            flash(f'Failed to {hide_str.lower()} thread', 'error')
    except Exception as e:
        flash(str(e), 'error')

    return redirect(request.form['redirect'])

@app.route('/comment/<int:comment_id>/hide/', methods = ['POST'])
def set_hide_comment(comment_id):
    chk, user = _moderator_check()
    if not chk:
        return user

    try:
        hide = request.form['hide'] != '0'
        hide_str = 'Hidden' if hide else 'Unhidden'
        if sql_db.set_comment_hidden(comment_id, hide):
            flash(f'{hide_str} comment', 'success')
        else:
            flash(f'Failed to {hide_str.lower()} comment', 'error')
    except Exception as e:
        flash(str(e), 'error')

    return redirect(request.form['redirect'])

# TODO can probably be a static-esque page, maybe?
@app.route('/help/')
def help():
    return template(
        'help.html',
        title = 'Help',
        user = get_user(),
    )

def _moderator_check():
    user = get_user()
    if user is None:
        return False, redirect(url_for('login'))
    if not user.is_moderator():
        return False, ('<h1>Forbidden</h1>', 403)
    return True, user

def _admin_check():
    user = get_user()
    if user is None:
        return False, redirect(url_for('login'))
    if not user.is_admin():
        return False, ('<h1>Forbidden</h1>', 403)
    return True, user


class Comment:
    def __init__(self, id, parent_id, author_id, author, text, create_time, modify_time, hidden):
        self.id = id
        self.author_id = author_id
        self.author = author
        self.text = text
        self.children = []
        self.create_time = create_time
        self.modify_time = modify_time
        self.parent_id = parent_id
        self.hidden = hidden

def create_comment_tree(comments, user):
    start = time.time();
    # Collect comments first, then build the tree in case we encounter a child before a parent
    comment_map = { v[0]: Comment(*v) for v in comments }
    root = []
    # We should keep showing hidden comments if the user replied to them, directly or indirectly.
    # To do that, keep track of user comments, then walk up the tree and insert hidden comments.
    user_comments = []
    # Build tree
    def insert(comment):
        parent = comment_map.get(comment.parent_id)
        if parent is not None:
            parent.children.append(comment)
        else:
            root.append(comment)
    for comment in comment_map.values():
        if comment.hidden and (not user or not user.is_moderator()):
            continue
        insert(comment)
        if user and (comment.author_id == user.id and not user.is_moderator()):
            user_comments.append(comment)
    # Insert replied-to hidden comments
    for c in user_comments:
        while c is not None:
            if c.hidden:
                insert(c)
            c = comment_map.get(c.parent_id)
    # Sort each comment based on create time
    def sort_time(l):
        l.sort(key=lambda c: c.modify_time, reverse=True)
        for c in l:
            sort_time(c.children)
    sort_time(root)
    return root


class User:
    def __init__(self, id, name, role, banned_until):
        self.id = id
        self.name = name
        self.role = role
        self.banned_until = banned_until

    def is_moderator(self):
        return self.role in (Role.ADMIN, Role.MODERATOR)

    def is_admin(self):
        return self.role == Role.ADMIN

    def is_banned(self):
        return self.banned_until > time.time_ns()

def get_user():
    id = session.get('user_id')
    if id is not None:
        name, role, banned_until = sql_db.get_user_name_role_banned(id)
        return User(id, name, role, banned_until)
    return None

def register_user(show_password):
    username, passwd = request.form['username'], request.form['password']
    if any(c in username for c in string.whitespace):
        # This error is more ergonomic in case someone tries to play tricks again :)
        flash('Username may not contain whitespace', 'error')
    elif len(username) < 3:
        flash('Username must be at least 3 characters long', 'error')
    elif len(passwd) < 8:
        flash('Password must be at least 8 characters long', 'error')
    elif not captcha.verify(
        config.captcha_key,
        request.form['captcha'],
        request.form['answer'],
    ):
        flash('CAPTCHA answer is incorrect', 'error')
    else:
        uid = sql_db.register_user(username, password.hash(passwd), time.time_ns())
        if uid is None:
            flash('Failed to create account (username may already be taken)', 'error')
        else:
            s = 'Account has been created.'
            if show_password:
                s += f' Your password is <code class=spoiler>{passwd}</code> (hover to reveal).'
            flash(s, 'success')
            uid, = uid
            session['user_id'] = uid
            session.permanent = True
            return True
    return False


@app.context_processor
def utility_processor():
    def _format_time_delta(n, t):
        # Try the sane thing first
        dt = (n - t) // 10 ** 9
        if dt < 1:
            return "less than a second"
        if dt < 2:
            return f"1 second"
        if dt < 60:
            return f"{dt} seconds"
        if dt < 119:
            return f"1 minute"
        if dt < 3600:
            return f"{dt // 60} minutes"
        if dt < 3600 * 2:
            return f"1 hour"
        if dt < 3600 * 24:
            return f"{dt // 3600} hours"
        if dt < 3600 * 24 * 31:
            return f"{dt // (3600 * 24)} days"

        # Try some very rough estimate, whatever
        f = lambda x: datetime.utcfromtimestamp(x // 10 ** 9)
        n, t = f(n), f(t)
        def f(x, y, s):
            return f'{y - x} {s}{"s" if y - x > 1 else ""}'
        if t.year < n.year:
            return f(t.year, n.year, "year")
        if t.month < n.month:
            return f(t.month, n.month, "month")
        assert False, 'unreachable'

    def format_since(t):
        n = time.time_ns()
        if n < t:
            return 'in a distant future'
        return _format_time_delta(n, t) + ' ago'

    def format_until(t):
        n = time.time_ns()
        if t <= n:
            return 'in a distant past'
        return _format_time_delta(t, n)

    def format_time(t):
        return datetime.utcfromtimestamp(t / 10 ** 9).replace(microsecond=0)

    def rand_password():
        '''
        Generate a random password.

        The current implementation returns 12 random lower- and uppercase alphabet characters.
        This gives up to `log((26 * 2) ** 12) / log(2) = ~68` bits of entropy, which should be
        enough for the foreseeable future.
        '''
        return ''.join(string.ascii_letters[secrets.randbelow(52)] for _ in range(12))

    def gen_captcha():
        return captcha.generate(config.captcha_key)

    return {
        'format_since': format_since,
        'format_time': format_time,
        'format_until': format_until,
        'minimd': minimd.html,
        'rand_password': rand_password,
        'gen_captcha': gen_captcha,
    }


def restart():
    '''
    Shut down *all* workers and spawn new ones.
    This is necessary on e.g. a configuration change.

    Since restarting workers depends is platform-dependent this task is delegated to an external
    program.
    '''
    r = subprocess.call(['./restart.sh'])
    if r == 0:
        flash('Restart script exited successfully', 'success')
    else:
        flash(f'Restart script exited with error (code {r})', 'error')

def trim_text(s):
    '''
    Because browsers LOVE \\r, trailing whitespace etc.
    '''
    return s.replace('\r', '')

