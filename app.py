from flask import Flask, render_template, redirect, url_for, request, flash, abort
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import random, string
import os
from datetime import datetime
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
import qrcode

base_dir = os.path.dirname(os.path.realpath(__file__))
db = SQLAlchemy()
app = Flask(__name__)



migrate = Migrate(app, db)


app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get('DATABASE_URI')
# 'sqlite:///' + os.path.join(base_dir, 'scissor.db')
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = "secret"
api = (os.environ.get("SENDGRID_API_KEY"))
login_manager = LoginManager()
login_manager.init_app(app)


db.init_app(app)
def generate_scissor_url(url):
    length = 6
    url = string.ascii_letters + string.digits
    scissor_url = ''.join(random.choice(url) for _ in range(length)).title()
    return scissor_url
class Scissor(db.Model):
    __tablename__ = "Blog"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=True)
    url = db.Column(db.String, unique=True, nullable=False)
    scissor_url = db.Column(db.String, unique=True, nullable=False)
    date_published = db.Column(db.DateTime)
    custom_url = db.Column(db.String, unique=True)
    gen_code = db.Column(db.Boolean, default=False)
    is_custom_url  = db.Column(db.Boolean, default=False)
    user = db.Column(db.String, default="Guest")

    def __repr__(self):
        return f"<Scissor {self.id}"


class User(db.Model, UserMixin):
    __tablename__ = "User"

    id = db.Column(db.Integer(), primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    username = db.Column(db.String(255), nullable=False, unique=True)
    is_individual = db.Column(db.Boolean, default=True)
    email = db.Column(db.String(255), nullable=False, unique=True)
    password_hash = db.Column(db.Text(), nullable=False)

    def __repr__(self):
        return f"{self.first_name}"


with app.app_context():
    db.create_all()


@login_manager.user_loader
def user_loader(user_id):
    return User.query.get(user_id)


@app.route('/', methods=['GET'])
def index():
    posts = Scissor.query.all()
    return render_template('index.html', posts=posts)


@app.route('/links')
def links():
    if current_user.is_authenticated:
        links = Scissor.query.filter_by(user=str(current_user)).all()
        print(os.path.join(app.static_folder))
        return render_template('auth_view/links.html', user_links=links)
    else:
        return redirect(url_for('login'))

@app.route('/home')
def home():
    # if current_user.is_authenticated:
#     #     blog = Scissor.query.filter_by(user=str(current_user)).all()
#     #     return render_template('auth/base.html', user_posts=blog)
#     # else:
#     #     return redirect(url_for('login'))
    return render_template('auth_view/dashboard.html')

@app.route('/create', methods=['GET', 'POST'])
# @login_required
def post():
    if request.method == "POST":
        title = request.form.get('title')
        url = request.form.get('url').strip('https://')
        date_published = datetime.now()
        gen_code = True if request.form.get('qrcode') else False
        user = current_user.first_name
        new_url = Scissor(title=title, url=url, scissor_url=generate_scissor_url(url), gen_code=gen_code, date_published=date_published, user=user)
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=20,
            border=4,
        )
        qr.add_data(url)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")
        image_path = os.path.join(app.static_folder,'img','sci-{}.png'.format(new_url.id))
        img.save(image_path)
        if new_url is None:
            flash("Error - Your post title or content is empty")
            return redirect(url_for('create'))
        else:
            db.session.add(new_url)
            db.session.commit()
            return redirect(url_for('links'))
    return render_template('auth_view/create.html')

@app.route('/qrcodes', methods=['GET'])
def qrcodes():
    if current_user.is_authenticated:
        links = Scissor.query.filter_by(user=str(current_user)).all()
        return render_template('auth_view/qrcodes.html', qr_links=links)

@app.route('/<string:url>')
def get_link(url):
    redirect_url = Scissor.query.filter_by(scissor_url=url).first()
    print(post)
    return redirect('https://'+redirect_url.url)

@app.route('/gencode', methods=['POST'])
def update_qr():
    link_id = request.form.get('record_id')
    qr = Scissor.query.get(link_id)
    qr.gen_code = True
    db.session.commit()

    return redirect('qrcodes')

@app.route('/url/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def edit_post(id):
    url = Scissor.query.get_or_404(id)
    if url.author != current_user.first_name:
        flash("You don't have permission to edit this url")
        return redirect(url_for('get_post', id=url.id))

        # abort(403, "<h1>You don't have permission to edit this post</h1>")

    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        url.title = title
        url.content = content
        db.session.commit()
        return redirect(url_for('get_post', id=url.id))
    else:

        return render_template('blog/edit_post.html', url=url)


@app.route('/url/<int:id>/delete', methods=['GET', 'POST'])
@login_required
def delete_post(id):
    link = Scissor.query.get_or_404(id)
    if link.author != current_user.first_name:
        abort(403)
    else:

        db.session.delete(link)
        db.session.commit()
        flash('Link deleted successfully')
        return redirect(url_for('links'))


@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/contact', methods=['GET', 'POST'])
def contact():
    print(os.environ.get("SENDGRID_API_KEY"))
    # using SendGrid's Python Library
    # https://github.com/sendgrid/sendgrid-python
    if request.method == 'POST':
        message = Mail(
            from_email='linibensonjr@gmail.com',
            to_emails='linibensojr@gmail.com',
            subject=request.form.get('subject'),
            html_content=request.form.get('message'))
        try:
            sg = SendGridAPIClient(os.environ.get('SENDGRID_API_KEY'))
            response = sg.send(message)
            print(response.status_code)
            print(response.body)
            print(response.headers)
            flash('Message sent successfully', category='success')
        except Exception as e:
            print(sg, e)
    return render_template('contact.html')


@app.route('/login', methods=['POST', 'GET'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    user = User.query.filter_by(username=username).first()

    if user and check_password_hash(user.password_hash, password):
        login_user(user)
        flash('You were successfully logged in')
        return redirect(url_for('home'))
    else:
        flash('Invalid username or password')
        return render_template('auth/login.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()
        if user:
            flash("Account already exists")
            return redirect(url_for('signup'))

        email_exists = User.query.filter_by(email=email).first()
        if email_exists:
            flash("Email already taken")
            return redirect(url_for('signup'))

        password_hash = generate_password_hash(password)

        new_user = User(first_name=first_name, last_name=last_name, username=username, email=email,
                        password_hash=password_hash)
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('login'))

    return render_template('auth/signup.html')


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


@login_manager.unauthorized_handler
def unauthorized():
    """Redirect unauthorized users to Login page."""
    flash('You must be logged in to view that page.')
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)

# @app.route('/', methods=['POST', 'GET'])
# def hello_world():
#
#     url = request.form.get('url')
#     sci = generate_scissor_url(url)
#     # return redirect('https://google.com')
#
#     return render_template('index.html', name=sci)

@app.route('/red', methods=['POST', 'GET'])
def red():
    url = request.form.get('url')
    sci = generate_scissor_url(url)
    return redirect('https://google.com')



if __name__ == '__main__':
    app.run()
