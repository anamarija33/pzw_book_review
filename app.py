from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from flask_bootstrap import Bootstrap5
from datetime import datetime, timezone
from pymongo import MongoClient
from bson.objectid import ObjectId
import gridfs
import markdown
from flask_login import UserMixin, LoginManager
from flask_login import login_required, current_user, login_user, logout_user
from forms import ReviewPostForm, LoginForm, RegisterForm, ProfileForm, UserForm
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message
from dotenv import load_dotenv
import os
from flask_principal import Principal, Permission, RoleNeed, Identity, identity_changed, identity_loaded, UserNeed, Need


app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')  # Ovo postavljamo kao tajni ključ za sigurnost
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')

bootstrap = Bootstrap5(app)
# client = MongoClient('mongodb://localhost:27017/')
client = MongoClient(os.getenv('MONGODB_CONNECTION_STRING'))
db = client['pzw_review_database']
reviews_collection = db['reviews']
titles_collection = db['titles']
users_collection = db['users']
fs = gridfs.GridFS(db)
mail = Mail(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

principal = Principal(app)
admin_permission = Permission(RoleNeed('admin'))
author_permission = Permission(RoleNeed('author'))

@login_manager.user_loader
def load_user(email):
    user_data = users_collection.find_one({"email": email})
    if user_data:
        return User(user_data['email'], user_data.get('is_admin'), user_data.get('theme'))

    return None

class User(UserMixin):
    def __init__(self, email, admin=False, theme=''):
        self.id = email
        self.admin = admin is True
        self.theme = theme

    @classmethod
    def get(self_class, id):
        try:
            return self_class(id)
        except UserNotFoundError:
            return None
        
    @property
    def is_admin(self):
        return self.admin

class UserNotFoundError(Exception):
    pass




@app.route("/", methods=["GET", "POST"])
def index():
    query = request.args.get('q', '').strip().lower()
 
    titles = titles_collection.find()
    titles_with_reviews = []

    for title in titles:
        reviews = []
        

        for review_id in title.get('reviews', []): 
            review = reviews_collection.find_one({'_id': review_id, 'status': 'published'})
            
            if review:
                if query:
                    if query in review['title'].lower() or \
                       query in review['book_author'].lower() or \
                       query in review['content'].lower():
                        reviews.append(review)
                else:
                    reviews.append(review)

        if reviews:
            titles_with_reviews.append({
                'title': title['title'],
                'book_author': title.get('book_author'),
                'reviews': reviews
            })
    
    return render_template('index.html', titles_with_reviews=titles_with_reviews, query=query)



@app.route('/review/create', methods=["get", "post"])
@login_required
def review_create():
    form = ReviewPostForm()
    if form.validate_on_submit():
        image_id = save_image_to_gridfs(request, fs)
        review = {
            'title': form.title.data,
            'book_author': form.book_author.data,
            'content': form.content.data,
            'author': current_user.get_id(),
            'status': form.status.data,
            'date': datetime.combine(form.date.data, datetime.min.time()),
            'tags': form.tags.data,
            'image_id': image_id,
            'date_created': datetime.utcnow()
        }
        
        inserted_id = reviews_collection.insert_one(review).inserted_id
        if review["status"] == 'published':
            title = titles_collection.find_one({'title':review["title"]})
            if title:
                titles_collection.update_one(
                    {'_id': title['_id']},  
                    {'$push': {'reviews': inserted_id}} 
                )
            else:
                titles_collection.insert_one({
                    'title': review["title"],
                    'book_author': review["book_author"],
                    'reviews': [inserted_id]  
                })
            


        flash('Recenzija je uspješno objavljena.', 'success')
        return redirect(url_for('index'))
    return render_template('review_edit.html', form=form)



@app.route('/review/<review_id>')
def review_view(review_id):
    review = reviews_collection.find_one({'_id': ObjectId(review_id)})

    if not review:
        flash("Recenzija nije pronađena!", "danger")
        return redirect(url_for('index'))

    return render_template('review_view.html', review=review, edit_review_permission=edit_review_permission)

@app.route('/review/edit/<review_id>', methods=["get", "post"])
@login_required
def review_edit(review_id):
    permission = edit_review_permission(review_id)
    if not permission.can():
        abort(403, "Nemate dozvolu za uređivanje ove recenzije.")

    form = ReviewPostForm()
    review = reviews_collection.find_one({"_id": ObjectId(review_id)})

    if request.method == 'GET':
        form.title.data = review['title']
        form.content.data = review['content']
        form.date.data = review['date']
        form.tags.data = review['tags']
        form.status.data = review['status']
    elif form.validate_on_submit():
        reviews_collection.update_one(
            {"_id": ObjectId(review_id)},
            {"$set": {
                'title': form.title.data,
                'content': form.content.data,
                'date': datetime.combine(form.date.data, datetime.min.time()),
                'tags': form.tags.data,
                'status': form.status.data,
                'date_updated': datetime.utcnow()
            }}
        )
        image_id = save_image_to_gridfs(request, fs)
        if image_id != None:
            reviews_collection.update_one(
            {"_id": ObjectId(review_id)},
            {"$set": {
                'image_id': image_id,
            }}
        )        
        flash('Članak je uspješno ažuriran.', 'success')
        return redirect(url_for('review_view', review_id = review_id))
    else:
        flash('Dogodila se greška!', category='warning')
    return render_template('review_edit.html', form=form)

@app.route('/review/delete/<review_id>', methods=['POST'])
@login_required
def delete_review(review_id):
    permission = edit_review_permission(review_id)
    if not permission.can():
        abort(403, "Nemate dozvolu za brisanje ove recenzije.")

    reviews_collection.delete_one({"_id": ObjectId(review_id)})
    flash('Recenzija je uspješno obrisana.', 'success')
    return redirect(url_for('index'))

def save_image_to_gridfs(request, fs):
    if 'image' in request.files:
        image = request.files['image']
        if image.filename != '':
            image_id = fs.put(image, filename=image.filename)
        else:
            image_id = None
    else:
        image_id = None
    return image_id

@app.route('/image/<image_id>')
def serve_image(image_id):
    image = fs.get(ObjectId(image_id))
    return image.read(), 200, {'Content-Type': 'image/jpeg'}

@app.template_filter('markdown')
def markdown_filter(text):
    return markdown.markdown(text)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = request.form['email']
        password = request.form['password']
        user_data = users_collection.find_one({"email": email})

        if user_data is not None and check_password_hash(user_data['password'], password):
            if not user_data.get('is_confirmed', False):
                flash('Molimo potvrdite vašu e-mail adresu prije prijave.', category='warning')
                return redirect(url_for('login'))
            user = User(user_data['email'])
            login_user(user, form.remember_me.data)
            identity_changed.send(app, identity=Identity(user.id))
            next = request.args.get('next')
            if next is None or not next.startswith('/'):
                next = url_for('index')
            flash('Uspješno ste se prijavili!', category='success')
            return redirect(next)
        flash('Neispravno korisničko ime ili zaporka!', category='warning')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Odjavili ste se.', category='success')
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        email = request.form['email']
        password = request.form['password']
        existing_user = users_collection.find_one({"email": email})

        if existing_user:
            flash('Korisnik već postoji', category='error')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        users_collection.insert_one({
            "email": email,
            "password": hashed_password,
            "is_confirmed": False
        })
        send_confirmation_email(email)
        flash('Registracija uspješna. Sad se možete prijaviti', category='success')
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

def generate_confirmation_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt='email-confirmation-salt')

def confirm_token(token, expiration=3600):  # Token expires in 1 hour
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(token, salt='email-confirmation-salt', max_age=expiration)
    except:
        return False
    return email

def send_confirmation_email(user_email):
    token = generate_confirmation_token(user_email)
    confirm_url = url_for('confirm_email', token=token, _external=True)
    html = render_template('email_confirmation.html', confirm_url=confirm_url)
    subject = "Molimo potvrdite email adresu"
    msg = Message(subject, recipients=[user_email], html=html)
    mail.send(msg)

@app.route('/confirm/<token>')
def confirm_email(token):
    try:
        email = confirm_token(token)
    except:
        flash('Link za potvrdu je neisprava ili je istekao.', 'danger')
        return redirect(url_for('unconfirmed'))

    user = users_collection.find_one({'email': email})
    if user['is_confirmed']:
        flash('Vaš račun je već potvrđen. Molimo prijavite se.', 'success')
    else:
        users_collection.update_one({'email': email}, {'$set': {'is_confirmed': True}})
        flash('Vaš račun je potvrđen. Hvala! Molimo prijavite se.', 'success')
    
    return redirect(url_for('login'))


def update_user_data(user_data, form):
    if form.validate_on_submit():
        db.users.update_one(
        {"_id": user_data['_id']},
        {"$set": {
            "first_name": form.first_name.data,
            "last_name": form.last_name.data,
            "bio": form.bio.data,
            "theme": form.theme.data
        }}
        )
        if form.image.data:
            # Pobrišimo postojeću ako postoji
            if hasattr(user_data, 'image_id') and user_data.image_id:
                fs.delete(user_data.image_id)
            
            image_id = save_image_to_gridfs(request, fs)
            if image_id != None:
                users_collection.update_one(
                {"_id": user_data['_id']},
                {"$set": {
                    'image_id': image_id,
                }}
            )
        flash("Podaci uspješno ažurirani!", "success")
        return True
    return False

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user_data = users_collection.find_one({"email": current_user.get_id()})
    form = ProfileForm(data=user_data)
    title = "Vaš profil"
    if update_user_data(user_data, form):
        return redirect(url_for('profile'))
    return render_template('profile.html', form=form, image_id=user_data.get("image_id"), title=title)

@app.route('/user/<user_id>', methods=['GET', 'POST'])
@login_required
@admin_permission.require(http_exception=403)
def user_edit(user_id):
    user_data = users_collection.find_one({"_id": ObjectId(user_id)})
    form = UserForm(data=user_data)
    title = "Korisnički profil"
    if update_user_data(user_data, form):
        return redirect(url_for('users'))
    return render_template('profile.html', form=form, image_id=user_data.get("image_id"), title=title)

@app.route("/myreviews")
def my_reviews():
    reviews = reviews_collection.find({"author": current_user.get_id()}).sort("date", -1)
    return render_template('my_reviews.html', reviews = reviews)


def localize_status(status):
    translations = {
        "draft": "Skica",
        "published": "Objavljen"
    }
    # Vrati prevedeni ili originalni ako nije pronađen
    return translations.get(status, status)

# Registirajmo filter za Jinja-u
app.jinja_env.filters['localize_status'] = localize_status


# Pomoćna metoda za provjeru prava uređivanja
def edit_review_permission(review_id):
    review = reviews_collection.find_one({'_id': ObjectId(review_id)})
    if not review:
        return Permission(RoleNeed('nonexistent')) # Effectively denies permission
    is_admin_or_author = current_user.is_admin or (current_user.get_id() == review.get('author'))
    
    if is_admin_or_author:
        return Permission(RoleNeed('allow_edit'))
    else:
        return Permission(RoleNeed('deny_edit'))

@identity_loaded.connect_via(app)
def on_identity_loaded(sender, identity):
    if current_user.is_authenticated:
        identity.user = current_user
        identity.provides.add(UserNeed(current_user.id))
        identity.provides.add(RoleNeed('author')) # Every authenticated user is considered an author
        if current_user.is_admin:
            identity.provides.add(RoleNeed('admin'))
            

@app.route('/users', methods=['GET', 'POST'])
@login_required
@admin_permission.require(http_exception=403)
def users():
    users = users_collection.find().sort("email")
    return render_template('users.html', users = users)

@app.errorhandler(403)
def access_denied(e):
    return render_template('403.html', description=e.description), 403

