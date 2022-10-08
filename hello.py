# FLASK_APP
from flask import Flask, render_template


# Create a FLask Instance

app = Flask(__name__)

# Create a route decorator
@app.route('/')

def index():
    return render_template('index.html')


@app.route('/user/<name>')

def user(name):
    return render_template('user.html', user_name=name)

if __name__=='__main__':
    app.run(debug=True)