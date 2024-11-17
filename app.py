from flask import Flask, request, render_template, flash, redirect, url_for, session, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask_uploads import UploadSet, configure_uploads, IMAGES
import random
import string
from authlib.integrations.flask_client import OAuth
import logging
from flask_session import Session
from werkzeug.utils import secure_filename
from it_quiz import it_quiz
from squiz import squiz
import os

app = Flask(__name__)


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_BINDS'] = {'admins': 'sqlite:///admins.db'}
app.config['SECRET_KEY'] = 'gbjwk34tjkb!@#$%^&*()6328964789tjkvgabsbgwegbkbdk!(%R$)'
app.config['UPLOADED_IMAGES_DEST'] = 'static/uploads'
app.config['SERVER_NAME'] = '127.0.0.1:5000'
app.config['SESSION_COOKIE_NAME'] = 'google-login-session'


images = UploadSet('images', IMAGES)
configure_uploads(app, images)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
oauth = OAuth(app)


app.register_blueprint(it_quiz, url_prefix='/it-quiz')
app.register_blueprint(squiz, url_prefix='/squiz')
def generate_nonce():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=16))

google = oauth.register(
    name='google',
    
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    client_kwargs={'scope': 'openid email profile'},
    server_metadata_uri='https://accounts.google.com/.well-known/openid-configuration',
    jwks_uri='https://www.googleapis.com/oauth2/v3/certs'
)




linkedin = oauth.register(
    'linkedin',
    
    request_token_params={
        'scope': 'openid profile email',
    },
    base_url='https://api.linkedin.com/v1/',
    request_token_url=None,
    access_token_method='POST',
    access_token_url='https://www.linkedin.com/uas/oauth/accessToken',
    authorize_url='https://www.linkedin.com/uas/oauth/authenticate'
)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# User model
class User(db.Model, UserMixin):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String, nullable=False)
    last_name = db.Column(db.String, nullable=False)
    grade = db.Column(db.Integer, nullable=False)
    t_no = db.Column(db.Integer, nullable=False)
    email = db.Column(db.String, nullable=False, unique=True)
    password = db.Column(db.String, nullable=True, unique=True)
    NIC = db.Column(db.String, nullable=True)
    pic = db.Column(db.String, nullable=True)
    status = db.Column(db.Integer, default=0, nullable=False)
    it_score = db.Column(db.Integer, default=0, nullable=True)
    science_score =db.Column(db.Integer, default=0, nullable=True)

    def __repr__(self):
        return f"<User {self.first_name} {self.last_name}>"


class Admin(db.Model, UserMixin):
    __bind_key__ = 'admins'
    __tablename__ = 'admins'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)

    def __repr__(self):
        return f'Admin("{self.username}", "{self.id}")'


@app.route('/')
def main():
    return render_template('main.html')


@app.route('/register', methods=['GET', 'POST'])
def reg():
    if request.method == 'POST':
        fm = request.form['f_name']
        lm = request.form['l_name']
        ga = request.form['grade']
        t = request.form['t_no']
        em = request.form['email']
        pa = request.form['password']
        nic = request.form['NIC']
        
        hp2 = bcrypt.generate_password_hash(pa)
        if em and pa:
            if 1 <= int(ga) <= 13:
                if 1 <= len(t) <= 10:
                    if len(pa) >= 8:
                        if not User.query.filter_by(email=em).first():
                            new_user = User(first_name=fm, last_name=lm, grade=ga, t_no=t, email=em, password=hp2, NIC=nic)
                            db.session.add(new_user)
                            db.session.commit()
                            flash('Registration successful! Please login.')
                            return redirect(url_for('login'))
                        else:
                            flash('Email already registered')
                    else:
                        flash('Password must be at least 8 characters')
                else:
                    flash('Invalid phone number')
            else:
                flash('Grade must be between 1 and 13')
        else:
            flash('Please fill out all fields')
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        ema = request.form['email']
        pas = request.form['password']

        if ema and pas:
            user = User.query.filter_by(email=ema).first()
            if user:
                if user.status == 1:  # Approved users only
                    if bcrypt.check_password_hash(user.password, pas):
                        login_user(user)
                        flash('Login successful')
                        return redirect(url_for('profile'))
                    else:
                        flash("Incorrect password")
                else:
                    flash("Account pending approval")
            else:
                flash("User does not exist")
        else:
            flash('Please fill in both fields')
    return render_template('login.html')





@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully')
    return redirect(url_for('login'))

# Profile route
@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')


@app.route('/update', methods=['GET', 'POST'])
@login_required
def update():
    return render_template('update.html')
@app.route('/backtoprofile', methods=['GET', 'POST'])

def backtoprofile():
    return redirect(url_for('profile'))

ALLOWED_EXTENSIONS ={'jpg', 'jpeg', 'png'}



@app.route('/updateprofile', methods=['POST', 'GET'])
@login_required
def updateprofile():
    if request.method == 'POST':
        # Get the current user record
        pd = User.query.get(current_user.id)

        # Get form data
        fn = request.form['first_name']
        ln = request.form['last_name']
        ga = request.form['grade']
        nic = request.form['nic']
        tn = request.form['t_no']
        em = request.form['email']
        pa = request.form['password']
        pic = request.files.get('reciept')

      
        if pa:
            hashed_password = bcrypt.generate_password_hash(pa).decode('utf-8')
            pd.password = hashed_password

        
        if pic and '.' in pic.filename:
            ext = pic.filename.rsplit('.', 1)[1].lower()
            if ext in ALLOWED_EXTENSIONS:
                filename = secure_filename(pic.filename)
                pic.save(os.path.join(app.config['UPLOADED_IMAGES_DEST'], filename))
                pd.pic = filename
            else:
                flash('Only JPG, JPEG, and PNG files are allowed.')
                return redirect(url_for('update'))  

       
        pd.first_name = fn
        pd.last_name = ln
        pd.grade = ga
        pd.NIC = nic
        pd.t_no = tn
        pd.email = em

        try:
            db.session.commit()  
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('profile'))  
        except Exception as e:
            flash(f'An error occurred: {e}', 'danger')
            return render_template('update.html')  


    return render_template('update.html') 




# Admin section
@app.route('/admin')
def admin():
    return render_template('admin/welcome.html')

@app.route('/logoutadmin')
def logoutadmin():
    logout_user()
    return redirect(url_for('login'))

@app.route('/admin/dashboard')
def admin_dashboard():
    total_user = User.query.count()
    total_approved = User.query.filter_by(status=1).count()
    total_pending = User.query.filter_by(status=0).count()
    return render_template('admin/admindashboard.html', title="Admin Dashboard", 
                           total_user=total_user, total_approved=total_approved, total_pending=total_pending)

@app.route('/admin/get-all-user', methods=["POST", "GET"])
def admin_get_all_user():
    search = request.form.get('search') if request.method == "POST" else None
    users = User.query.filter(User.first_name.like(f'%{search}%')).all() if search else User.query.all()
    return render_template('admin/all.html', title='Approve User', users=users)

@app.route('/admin/approve-user/<int:id>')
def admin_approve(id):
    user = User.query.get(id)
    if user:
        user.status = 1
        db.session.commit()
        flash('User approved successfully', 'success')
    else:
        flash('User not found', 'danger')
    return redirect(url_for('admin_get_all_user'))
#
@app.route('/login/google')
def login_google():
   
    nonce = generate_nonce()
    session['nonce'] = nonce  
    
    redirect_uri = url_for('auth', _external=True)
    
    # Pass the nonce in the authorization request
    return google.authorize_redirect(redirect_uri, nonce=nonce)
@app.route('/authorized/google')
def auth():
    try:
        
        nonce = session.get('nonce')
        
       
        token = google.authorize_access_token()
        
        
        user_info = google.parse_id_token(token, nonce=nonce)
        print(user_info)  
       
        user = User.query.filter_by(email=user_info['email']).first()
        if user :
            if user.status == 1:
                login_user(user)
                flash('successful')
                return redirect(url_for('profile'))
            else:
                flash('pending approval')
                return redirect(url_for('login'))
        else:
            return redirect(url_for('reg'))    
    except Exception as e:
        flash(f'An error occurred: {e}', 'danger')
        return redirect(url_for('login'))
    




def create_db():
    with app.app_context():
        db.create_all()




if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    app.run(debug=True)