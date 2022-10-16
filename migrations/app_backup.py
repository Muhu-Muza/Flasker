from flask import Flask, render_template, flash, request, redirect,url_for
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField, ValidationError
from wtforms.validators import DataRequired, EqualTo, Length
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms.widgets import TextArea
from flask_login import UserMixin, login_manager, login_user, LoginManager,logout_user,login_required,current_user

# Create a FLask Instance

app = Flask(__name__)

# ADD DATABASE
# Old SQLite db
    # app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
# NEW MYSQL db
    # app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://username:password@localhost/db_name'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:Pioneer4@localhost/users'

# secret Key
app.config['SECRET_KEY'] = "my secret key that no one is supposed to see"

# Initialise the database
db = SQLAlchemy(app)
migrate = Migrate(app, db)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

# Create Model
class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable = False, unique =True ) 
    name = db.Column(db.String(200), nullable = False)
    email = db.Column(db.String(100), nullable = False, unique = True)
    favorite_color = db.Column(db.String(120))
    date_added = db.Column(db.DateTime, default = datetime.utcnow)
    password_hash = db.Column(db.String(128))

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute!')
    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)
    # Create a string
    def __repr__(self):
        return '<Name %r>' % self.name


class Posts(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    title = db.Column(db.String(255))
    content = db.Column(db.Text)
    author = db.Column(db.String(255))
    date_posted = db.Column(db.DateTime, default = datetime.utcnow)
    slug = db.Column(db.String(255))

# Create a PostForm

class PostForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired()])
    content = StringField("Content", validators=[DataRequired()], widget = TextArea())
    author = StringField("Author", validators=[DataRequired()])
    slug = StringField("Slug", validators=[DataRequired()])
    submit = SubmitField("Submit")

# Create a form class
class NamerForm(FlaskForm):
    name = StringField("What's Your Name", validators=[DataRequired()])
    submit = SubmitField("Submit")


class UserForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    username = StringField("Username", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired()])
    favorite_color = StringField("Favorite Color")
    password_hash = PasswordField('Password', validators=[DataRequired(), EqualTo('password_hash2', message='Passwords Must Match')])
    password_hash2 = PasswordField('Confirm Password', validators=[DataRequired()])
    submit = SubmitField("Submit")


class LoginForm(FlaskForm):
    username = StringField("Username", validators = [DataRequired()])
    password = PasswordField("Password", validators = [DataRequired()])
    submit = SubmitField("Submit")
@app.route('/login', methods=['GET', "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit:
        user = Users.query.filter_by(username = form.username.data).first()
        if user:
            if check_password_hash(user.password_hash, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
            else:
                flash("Wrong password - Try again!")
        else:
            flash("User Does'nt exist!")

    return render_template('login.html' , form = form)

@app.route('/dashboard', methods=['GET', "POST"])
@login_required
def dashboard():
    form = UserForm()
    id = current_user.id
    name_to_update = Users.query.get_or_404(id)
    if request.method == 'POST':
        name_to_update.name = request.form['name']
        name_to_update.email = request.form['email']
        name_to_update.favorite_color = request.form['favorite_color']
        name_to_update.username = request.form['username']
        try:
            db.session.commit()
            flash("User Updated Successfully!")
            return render_template("dashboard.html",
                            form = form,
                            name_to_update = name_to_update
                            )
        except:
            flash("Error!!! Looks like there was a problem...try again")
            return render_template("dashboard.html",
                            form = form,
                            name_to_update = name_to_update
                            )
    else:
        return render_template("dashboard.html",
                            form = form,
                            name_to_update = name_to_update,
                            id = id
                            )

@app.route('/logout', methods=['GET', "POST"])
@login_required
def logout():
    logout_user()
    flash("You have logged out")
    return redirect(url_for('login'))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/user/<name>')
def user(name):
    return render_template('user.html', user_name=name)

@app.route('/name', methods=['GET','POST'])
def name():
    name = None
    form = NamerForm()

    if form.validate_on_submit():
        name = form.name.data
        form.name.data = ''
        flash("Form Submitted Successfully")

    return render_template('name.html', name = name, form = form)

@app.route('/user/add', methods=['GET', 'POST'])
def add_user():
    name = None
    form = UserForm()   
    if form.validate_on_submit():
        user = Users.query.filter_by(email=form.email.data).first()
        if user is None:
            # Hash the password!!!
            hashed_pw = generate_password_hash(form.password_hash.data, "sha256")
            user = Users(name=form.name.data, username=form.username.data,email=form.email.data, favorite_color = form.favorite_color.data, password_hash = hashed_pw)
            db.session.add(user)
            db.session.commit()
        name = form.name.data
        form.name.data = ''
        form.username.data = ''
        form.email.data = ''
        form.favorite_color.data = ''
        form.password_hash = ''
        flash("User Added Succesfully")
    our_users = Users.query.order_by(Users.date_added)
    return render_template("add_user.html",
                             form = form,
                             name = name,
                             our_users=our_users)

@app.route('/add-post', methods = ['GET', 'POST'])
# @login_required
def add_post():
    form = PostForm()
    if form.validate_on_submit():
        post = Posts(title = form.title.data, content =form.content.data, author = form.author.data, slug = form.slug.data)
        form.title.data = ''
        form.content.data = ''
        form.author.data = ''
        form.slug.data = ''

        db.session.add(post)
        db.session.commit()

        flash("Blog Post Submitted Successfully!")
    return render_template("add_post.html", form = form)

@app.route('/update/<int:id>' , methods = ['POST', 'GET'])
def update(id):
    form = UserForm()
    name_to_update = Users.query.get_or_404(id)
    if request.method == 'POST':
        name_to_update.name = request.form['name']
        name_to_update.email = request.form['email']
        name_to_update.favorite_color = request.form['favorite_color']
        name_to_update.username = request.form['username']
        try:
            db.session.commit()
            flash("User Updated Successfully!")
            return render_template("update.html",
                            form = form,
                            name_to_update = name_to_update
                            )
        except:
            flash("Error!!! Looks like there was a problem...try again")
            return render_template("update.html",
                            form = form,
                            name_to_update = name_to_update
                            )
    else:
        return render_template("update.html",
                            form = form,
                            name_to_update = name_to_update,
                            id = id
                            )

@app.route('/delete/<int:id>')
def delete(id):
    name = None
    form = UserForm()
    user_to_delete = Users.query.get_or_404(id)
    try:
        db.session.delete(user_to_delete)
        db.session.commit()
        flash("User Deleted Successfully!!!")
        our_users = Users.query.order_by(Users.date_added)
        return render_template("add_user.html",
                                form = form,
                                name = name,
                                our_users=our_users)
    except:
        flash("WHoops! There was a problem deleting the user !!! Try again!!!")
        return render_template("add_user.html",
                                form = form,
                                name = name,
                                our_users=our_users)

@app.route('/posts')
def posts():

    posts = Posts.query.order_by(Posts.date_posted)
    return render_template("posts.html", posts = posts)

@app.route('/posts/<int:id>')
def post(id):
    post = Posts.query.get_or_404(id)
    return render_template('post.html', post = post)

@app.route('/posts/edit/<int:id>', methods = ['GET','POST'])
@login_required
def edit_post(id):
    post =Posts.query.get_or_404(id)
    form = PostForm()
    if form.validate_on_submit():
        post.title = form.title.data
        post.author = form.author.data
        post.slug = form.slug.data
        form.content = form.content.data

        db.session.add(post)
        db.session.commit()
        flash("post has been updated!")
        return redirect(url_for('post', id=post.id))

    form.title.data = post.title
    form.author.data = post.author
    form.slug.data = post.slug
    form.content.data = post.content
    return render_template('edit_post.html', form = form)

@app.route('/posts/delete/<int:id>')
def delete_post(id):
    post_to_delete = Posts.query.get_or_404(id)

    try:
        db.session.delete(post_to_delete)
        db.session.commit()

        flash("Blog Post Deleted!")
        posts = Posts.query.order_by(Posts.date_posted)
        return render_template("posts.html", posts = posts)

    except:
        flash("Whoops! There was a problem deleting the post")
        posts = Posts.query.order_by(Posts.date_posted)
        return render_template("posts.html", posts = posts)










if __name__=='__main__':
    app.run(debug=True)