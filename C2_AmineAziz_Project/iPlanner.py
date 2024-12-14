from flask import Flask, render_template, request, flash, session, redirect, url_for, make_response
from flask_wtf.csrf import CSRFProtect
from markupsafe import escape
import sqlite3

csrf = CSRFProtect() #putting in place CSRFProtect
app = Flask(__name__)
app.secret_key = 'x1x2x3x4'
csrf.init_app(app)


def TaskDB_conn(): 
    conn = sqlite3.connect('TaskListDB.db', timeout=10.0)
    conn.row_factory = sqlite3.Row
    return conn

@app.after_request #enhancement of Content Security Policy
def apply_csp_header(resp):
    resp.headers['Content-Security-Policy'] = ( "default-src 'self'; " "img-src 'self' data:; " "font-src 'self'" )
    resp.headers['X-XSS-Protection'] = '1; mode=block' # XSS security if using an older browsers)
    resp.headers['X-Frame-Options'] = 'DENY' #protect against clickjacking
    resp.headers['X-Content-Type-Options'] = 'nosniff' # protect against sniffing
    return resp

@app.route('/')
@app.route('/homepage', methods=['GET', 'POST'])
def index():
    return render_template('homepage.html')
    
@app.route('/', methods=['GET', 'POST'])
def login():
    error = None    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = TaskDB_conn()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM Users WHERE username = ? AND password = ?', (username, password))
        user = cursor.fetchone()
        conn.close()
        
        if user and username == user['username'] and password == user['password']:
            session['secured_session_step2'] = username #secure session
            resp = make_response(redirect(url_for('iPlanner')))
            resp.set_cookie('securedcookie_step1', username, httponly=True, secure=True, samesite='Strict', max_age=60)
            return resp
        else:
             error='invalid'
             flash(error)
    return render_template('homepage.html',error=error)

@app.route('/iPlanner', methods=['GET', 'POST'])
def iPlanner():
    sec_session=session.get('secured_session_step2')
    user = request.cookies.get('securedcookie_step1') #secure session
    task = request.form.get('ListTask')
    secured_task=escape(task) #sanitized
    if not user:
        return redirect(url_for('login'))
        
    if request.method == 'POST':
        if secured_task:
            conn = TaskDB_conn()
            cursor = conn.cursor()
            cursor.execute('INSERT INTO Tasks (content) VALUES (?)', (secured_task,))
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
        secured_newtask=escape(newTask) #sanitized
        cursor.execute('UPDATE Tasks SET content = ? WHERE id = ?', (secured_newtask,id,))
        conn.commit()
        conn.close()
        return redirect(url_for('iPlanner'))
    conn = TaskDB_conn()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM Tasks WHERE id = ?',(id,))
    contents = cursor.fetchone()
    conn.close()
    return render_template('newTask.html', contents=contents)


@app.route('/deleteTask/<int:id>', methods=['GET', 'POST'])
def deleteTask(id):
    conn = TaskDB_conn()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM Tasks WHERE id = ?', (id,))
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
    resp.set_cookie('securedcookie_step1', expires=0)
    return resp

if __name__ == '__main__':
    app.run(debug=True, port=8001)

if __name__ == '__main__':
    # init_db()
    # context = ('cert.crt', 'private.key')
    # app.run(debug=True, ssl_context=context)
    context='adhoc'
    app.run(debug=True, ssl_context=context)
