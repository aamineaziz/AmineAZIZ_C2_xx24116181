from flask import Flask, render_template, request, flash, session, redirect, url_for, make_response
import sqlite3

app = Flask(__name__)
app.secret_key = 'x1x2x3x4'

def TaskDB_conn(): 
    conn = sqlite3.connect('TaskListDB.db', timeout=10.0)
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
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
    if request.method == 'POST':
        error = None
        username = request.form['username']
        password = request.form['password']
        conn = TaskDB_conn()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM Users WHERE username = ? AND password = ?', (username, password))
        user = cursor.fetchone()
        conn.close()
        
        if username == user['username'] and password == user['password']:
        # session['username']== user['username']:
            resp = make_response(redirect(url_for('iPlanner')))
            resp.set_cookie('user', username, max_age=60*60*24)
            return resp
        else:
             flash('wrong')
            #render_template('homepage.html',error=error)
    return render_template('homepage.html',error=error)
# 
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
    
@app.route('/deleteTask', methods=['GET'])
def deleteTask():
    conn = TaskDB_conn()
    cursor = conn.cursor()
    
    if request.method == 'GET':
        theId = request.form.get('ListTask')
        cursor.execute('DELETE FROM Tasks WHERE id = ?', (theId,))
        conn.commit()
        conn.close()
        return redirect(url_for('iPlanner.html'))
if __name__ == '__main__':
    # init_db()
    app.run(debug=True, port=5000)
