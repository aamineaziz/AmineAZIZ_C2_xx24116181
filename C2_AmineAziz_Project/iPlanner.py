from flask import Flask, render_template, request, flash, session, redirect, url_for, make_response
import sqlite3

app = Flask(__name__)
app.secret_key = 'x1x2x3x4'

def TaskDB_conn(): 
conn = sqlite3.connect('TaskListDB.db')
conn.row_f = sqlite3.Row
return conn
# conn = sqlite3.connect("TaskListDB.db")
# cursor = connection.cursor()
# cursor.execute("""
# CREATE TABLE IF NOT EXISTS users (
    # id INTEGER PRIMARY KEY AUTOINCREMENT,
    # name TEXT NOT NULL,
    # age INTEGER
# )
# """)
# cursor.execute("INSERT INTO users (name, age) VALUES (?, ?)", ("Alice", 30))
# cursor.execute("SELECT * FROM users")
# rows = cursor.fetchall()
# for row in rows:
    # print(row)
# connection.commit()
# connection.close()
@app.route('/')
def index():
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
        
        if user:
            session['username']= user['username']
            resp = make_response(redirect(url_for('iPlanner')))
            resp.set_cookie('user', username, max_age=60*60*24)
            return resp
        else:
            flash('wrong username or password')
        # if username == 'admin' and password == 'admin':
            
    return render_template('homepage.html',error=error)

@app.route('/iPlanner', methods=['GET', 'POST'])
def iPlanner():

    user = request.cookies.get('user')
    if not user:
        return redirect(url_for('login'))
    if request.method == 'POST':
        text = request.form.get('ListTask')
        return render_template('iPlanner.html', user=user, text=text)
    return render_template('iPlanner.html')

if __name__ == '__main__':
init_db()
    app.run(debug=True, port=5000)
