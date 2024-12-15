from flask import Flask, render_template, request, flash, session, redirect, url_for, make_response
from flask_wtf.csrf import CSRFProtect
from markupsafe import escape
import sqlite3
import re
import logging
import os

csrf = CSRFProtect() #putting in place CSRFProtect
app = Flask(__name__)
app.secret_key = 'x1x2x3x4'
# SECRET_KEY = os.environ["SECRET_KEY"]
# app.secret_key = SECRET_KEY
# this is not added for the sake of the project otherwise the app won't run unless you add the variable in to the os envirement 


logging.basicConfig(filename='iPlanner.log', level=logging.WARNING, #a way to log your activities
                    format='%(asctime)s - %(message)s')
                    
logger = logging.getLogger(__name__)

csrf.init_app(app)

@app.route('/refresh_to_Main', methods=['GET'])
def refresh_to_Main():
    return redirect(url_for('iPlanner'))

def TaskDB_conn(): #database init
    conn = sqlite3.connect('TaskListDB.db', timeout=10.0)
    conn.row_factory = sqlite3.Row
    return conn

def TaskDB_conn_RO(): #database init
    conn = sqlite3.connect('file:TaskListDB.db?mode=ro', uri=True)
    conn.row_factory = sqlite3.Row
    return conn


@app.after_request #enhancement of Content Security Policy
def apply_csp_header(resp):
    resp.headers['Content-Security-Policy'] = ( "default-src 'self'; " "img-src 'self' data:; " "font-src 'self'" )
    resp.headers['X-XSS-Protection'] = '1; mode=block' # XSS security if using an older browsers)
    resp.headers['X-Frame-Options'] = 'DENY' #protect against clickjacking
    resp.headers['X-Content-Type-Options'] = 'nosniff' # protect against sniffing
    return resp


# def password_is_valid():
    # conn = TaskDB_conn()
    # cursor = conn.cursor()
    # cursor.execute('SELECT * FROM Users WHERE username = ? AND password = ?', (username, password)) # Prevent SQL injection with parametrized sql query
    # user = cursor.fetchone()
    # conn.close()
    # if user and username == user['username'] and password == user['password']:
        # session['secured_session_step2'] = username #secure session
        # resp = make_response(redirect(url_for('iPlanner')))
        # resp.set_cookie('securedcookie_step1', username, httponly=True, secure=True, samesite='Strict', max_age=60)
        # return resp
    # return render_template('homepage.html',error=error)


# @app.route('/', methods=['GET', 'POST'])
# def check_if_valid():
    # password = request.form['password']
    # hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    # return hashed_password

#did not implement a registration form and didnt have time to add a table that stores hashes to compare to.



def is_valid(the_input, allowed_cha="^[a-zA-Z0-9_ ]+$"):
    return bool(re.match(allowed_cha, the_input))

@app.route('/')
@app.route('/homepage', methods=['GET', 'POST'])
def index():
    return render_template('homepage.html')
    
@app.route('/', methods=['GET', 'POST'])
def login():
    error = None
    non_alpha_num_error = None
    Update_invalid_error = None
    if request.method == 'POST':
        
        username = request.form['username']
        password = request.form['password']
        
        if not is_valid(username) or not is_valid(password):
            non_alpha_num_error='Please use alphanumeric characters'
            logger.warning('Suspicious input detected: %s', non_alpha_num_error) # log in case of error
            flash(non_alpha_num_error)
            return render_template('homepage.html',non_alpha_num_error = non_alpha_num_error)
        
        conn = TaskDB_conn()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM Users WHERE username = ? AND password = ?', (username, password)) # Prevent SQL injection with parametrized sql query
        user = cursor.fetchone()
        conn.close()
        
        if user and username == user['username'] and password == user['password']:
            session['secured_session_step2'] = username #secure session
            resp = make_response(redirect(url_for('iPlanner')))
            resp.set_cookie('securedcookie_step1', username, httponly=True, secure=True, samesite='Strict', max_age=60)
            resp.set_cookie('role', user['role'], httponly=True, secure=True, samesite='Strict', max_age=60) #storing role to user for RBAC verification
            return resp
        else:
             error='Invalid Credentials'
             flash(error)
    return render_template('homepage.html',error=error)

@app.route('/viewOnly', methods=['GET'])
def viewOnly(): #function to just view content
    conn = TaskDB_conn_RO()# making the DB read only
    cursor = conn.cursor()
    cursor.execute('SELECT id, content FROM Tasks ORDER BY id DESC;')
    contents = cursor.fetchall()
    conn.close()
    return render_template('viewOnly.html', contents=contents)

@app.route('/iPlanner', methods=['GET', 'POST'])
def iPlanner():
    sec_session=session.get('secured_session_step2')
    user = request.cookies.get('securedcookie_step1') #secure session
    task = request.form.get('ListTask')
    role = request.cookies.get('role')
    if not is_valid(str(task)):
            non_alpha_num_error='Please use alphanumeric characters'
            logger.warning('Suspicious input detected: %s', non_alpha_num_error)# log in case of error
            flash(non_alpha_num_error)
            return render_template('iPlanner.html',non_alpha_num_error = non_alpha_num_error)
    
    refresh_to_Main()
    
    secured_task=escape(task) #sanitized
    
    if not user:
        return redirect(url_for('login'))
    if role == 'guest': #RBAC based on the guest user that only sees the tasks and cant modify them
        return redirect(url_for('viewOnly'))
    
    if request.method == 'POST':
        if secured_task:
            conn = TaskDB_conn()
            cursor = conn.cursor()
            cursor.execute('INSERT INTO Tasks (content) VALUES (?)', (secured_task,)) # Prevent SQL injection with parametrized sql query
            conn.commit()
            conn.close()
    conn = TaskDB_conn()
    cursor = conn.cursor()
    cursor.execute('SELECT id, content FROM Tasks ORDER BY id DESC;')
    contents = cursor.fetchall()
    conn.close()
    return render_template('iPlanner.html', user=user, contents=contents)
    
@app.route('/newTask/<int:id>', methods=['GET', 'POST'])
def newTask(id):
    conn = TaskDB_conn()
    cursor = conn.cursor()
    
    if request.method == 'POST':
        newTask = request.form.get('ListTask')
        if not is_valid(newTask):
            Update_invalid_error='You tried to Update with invalid characters'
            logger.warning('Suspicious input detected: %s', Update_invalid_error) # log in case of error
            flash(Update_invalid_error)
            return refresh_to_Main()
        
        secured_newtask=escape(newTask) #sanitized
        cursor.execute('UPDATE Tasks SET content = ? WHERE id = ?', (secured_newtask,id,)) # Prevent SQL injection with parametrized sql query
        conn.commit()
        conn.close()
        return redirect(url_for('iPlanner'))
    conn = TaskDB_conn()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM Tasks WHERE id = ?',(id,)) # Prevent SQL injection with parametrized sql query
    contents = cursor.fetchone()
    conn.close()
    return render_template('newTask.html', contents=contents)


@app.route('/deleteTask/<int:id>', methods=['GET', 'POST'])
def deleteTask(id):
    conn = TaskDB_conn()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM Tasks WHERE id = ?', (id,)) # Prevent SQL injection with parametrized sql query
    conn.commit()
    conn.close()
    return redirect(url_for('iPlanner'))
    
@app.route('/deleteAllTasks', methods=['GET', 'POST'])
def deleteAllTasks():
    conn = TaskDB_conn()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM Tasks') 
    conn.commit()
    conn.close()
    return redirect(url_for('iPlanner'))
    
@app.route('/logout')
def logout():
    resp = make_response(redirect(url_for('login')))
    resp.set_cookie('securedcookie_step1', httponly=True, secure=True, samesite='Strict',expires=0)
    return resp


@app.errorhandler(500) # Handeling wrong access
def internal_error(error):
    logger.error('Server Error: %s', (error))
    return render_template('500.html'), 500

@app.errorhandler(404) # Handeling wrong access
def not_found_error(error):
    logger.error('Page Not Found: %s', (error))
    return render_template('404.html'), 404


if __name__ == '__main__':
    app.run(debug=True, port=8001)

if __name__ == '__main__':
    # init_db()
    # context = ('cert.crt', 'private.key')
    # app.run(debug=False, ssl_context=context)
    context='adhoc'
    app.run(debug=True, ssl_context=context)
