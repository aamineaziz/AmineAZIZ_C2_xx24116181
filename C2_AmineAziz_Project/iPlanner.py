from flask import Flask, render_template, request, flash, session, redirect, url_for, make_response
import sqlite3

app = Flask(__name__)
app.secret_key = 'x1x2x3x4'

def TaskDB_conn(): 
    conn = sqlite3.connect('TaskListDB.db', timeout=10.0)
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
@app.route('/homepage', methods=['GET', 'POST'])
def index():
    if 'username' in session:
        conn = sqlite3.connect('TaskListDB.db', timeout=10.0)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM Tasks')
        tasks = cursor.fetchall()
        conn.close()
        return redirect(url_for('iPlanner', tasks=tasks))
    return render_template('homepage.html')
    
@app.route('/', methods=['GET', 'POST'])
def login():
    # if request.method == 'POST':
        # username = request.form['username']
        # password = request.form['password']
        # conn = TaskDB_conn()
        # cursor = conn.cursor()
        # cursor.execute('SELECT * FROM Users WHERE username = ? AND password = ?', (username, password))
        # if not cursor.fetchone():
            # return render_template('homepage.html')
        # else:
            # return render_template('iPlanner.html', name = username)
    # else:
        # request.method == 'GET':
        # return render_template('homepage.html')
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
        # session['username']== user['username']:
            resp = make_response(redirect(url_for('iPlanner')))
            # make_response(redirect(url_for('iPlanner')))
            resp.set_cookie('user', username, max_age=60*60*24)
            return resp
        else:
             error='invalid'
             flash(error)# flash('wrong')
            # #render_template('homepage.html',error=error),error=error
    return render_template('homepage.html',error=error)

@app.route('/iPlanner', methods=['GET', 'POST'])
def iPlanner():
    user = request.cookies.get('user')
    task = request.form.get('ListTask')
    if not user:
        return redirect(url_for('login'))
        
    if request.method == 'POST':
        if task:
            conn = TaskDB_conn()
            cursor = conn.cursor()
            cursor.execute('INSERT INTO Tasks (content) VALUES (?)', (task,))
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
        cursor.execute('UPDATE Tasks SET content = ? WHERE id = ?', (newTask,id,))
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
    resp.set_cookie('user', expires=0)
    return resp

if __name__ == '__main__':
    # init_db()
    app.run(debug=True, port=5000)
