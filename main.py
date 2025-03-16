from flask import Flask, render_template, request, redirect, url_for, flash, sessions, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import secrets
from authlib.integrations.flask_client import OAuth
import requests
from datetime import datetime
import os

app = Flask(__name__)
# app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
app.config['GOOGLE_CLIENT_ID'] = os.environ.get('GOOGLE_CLIENT_ID')
app.config['GOOGLE_CLIENT_SECRET'] = os.environ.get('GOOGLE_CLIENT_SECRET')
app.secret_key = secrets.token_hex(16)

oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    client_kwargs={'scope': 'openid email profile'},
    jwks_uri = "https://www.googleapis.com/oauth2/v3/certs"
)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

from datetime import datetime

@app.template_filter('datetimeformat')
def datetimeformat(value, format='%d %b %Y %I:%M %p'):
    if isinstance(value, str):
        value = datetime.fromisoformat(value)
    return value.strftime(format)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    phone = db.Column(db.String(20), nullable=True)
    bio = db.Column(db.Text, nullable=True)
    photo = db.Column(db.String(200), nullable=True)
    password_hash = db.Column(db.String(200), nullable=False)
    google_id = db.Column(db.String(200), unique=True, nullable=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        data = request.form
        hashed_password = generate_password_hash(data['password'])
        
        photo_path = None
        
        if 'photo' in request.files:
            file = request.files['photo']
            if file and file.filename != '':
                if allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    photo_path = f"uploads/{filename}"
        
        # If no file uploaded, use URL
        if not photo_path and data.get('photo_url'):
            photo_path = data['photo_url']
        
        new_user = User(
            name=data['name'],
            email=data['email'],
            phone=data.get('phone'),
            bio=data.get('bio'),
            photo=photo_path,
            password_hash=hashed_password
        )
        
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except:
            db.session.rollback()
            flash('Email already exists!', 'danger')
        
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.form
        user = User.query.filter_by(email=data['email']).first()
        if not user or not check_password_hash(user.password_hash, data['password']):
            flash('Invalid email or password', 'danger')
            return redirect(url_for('login'))
        login_user(user)
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/login/google')
def google_login():
    redirect_uri = url_for('google_authorize', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/login/google/authorize')
def google_authorize():
    try:
        token = google.authorize_access_token()
        resp = google.get('userinfo')
        user_info = resp.json()
        
        # Extract user data from Google
        google_id = user_info['id']
        email = user_info['email']
        name = user_info.get('name', '')
        photo = user_info.get('picture', None)
        
        # Find or create user
        user = User.query.filter_by(google_id=google_id).first()
        if not user:
            user = User.query.filter_by(email=email).first()
            if user:
                # Merge existing email account with Google
                user.google_id = google_id
            else:
                # Create new user
                user = User(
                    google_id=google_id,
                    email=email,
                    name=name,
                    photo=photo,
                    password_hash='google-auth'  # Placeholder
                )
                db.session.add(user)
            db.session.commit()
        
        login_user(user)
        return redirect(url_for('dashboard'))
    
    except Exception as e:
        print(e)
        flash('Google login failed', 'danger')
        return redirect(url_for('login'))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out', 'success')
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user=current_user)

@app.route('/edit-profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    user = current_user
    
    if request.method == 'POST':
        data = request.form
        user.name = data.get('name', user.name)
        user.phone = data.get('phone', user.phone)
        user.bio = data.get('bio', user.bio)
        
        # Handle password change
        if data.get('password'):
            user.password_hash = generate_password_hash(data['password'])
        
        # Handle photo update
        if 'photo' in request.files:
            file = request.files['photo']
            if file and file.filename != '':
                if allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    user.photo = f"uploads/{filename}"
        elif data.get('photo_url'):
            user.photo = data['photo_url']
        
        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('edit_profile.html', user=user)

@app.route('/weather')
@login_required
def weather():
    try:
        # Fetch data from the API
        response = requests.get('https://api.data.gov.sg/v1/environment/air-temperature')
        data = response.json()
        
        # Extract relevant information
        timestamp = data['items'][0]['timestamp']
        stations = []
        
        # Match readings with station metadata
        station_metadata = {s['id']: s for s in data['metadata']['stations']}
        for reading in data['items'][0]['readings']:
            station_id = reading['station_id']
            station_info = station_metadata.get(station_id, {})
            stations.append({
                'name': station_info.get('name', 'Unknown Station'),
                'temperature': reading['value'],
                'location': station_info.get('location', {})
            })
       
        return render_template('weather.html', 
                            timestamp=timestamp,
                            stations=stations)
        
    except Exception as e:
        print(e)
        flash('Failed to fetch weather data', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/get_all_coins', methods=['GET'])
def get_all_coins():
    url = "https://data-api.binance.vision/api/v3/ticker/24hr"
    res = requests.get(url).json()
    tickers = [{'symbol': r['symbol']} for r in res]
    return jsonify(tickers)

@app.route('/crypto')
@login_required
def crypto():
    return render_template('crypto.html')

@app.route('/get_coins')
def get_coins():
    page = request.args.get('page', 1, type=int)
    per_page = 50
    search = request.args.get('search', '').upper()
    
    response = requests.get('https://data-api.binance.vision/api/v3/ticker/24hr')
    if response.status_code != 200:
        return jsonify([])
    
    all_coins = response.json()
    # Sort by weightedAvgPrice in descending order
    sorted_coins = sorted(all_coins, 
                         key=lambda x: float(x['weightedAvgPrice']), 
                         reverse=True)
    filtered_coins = [coin for coin in sorted_coins if search in coin['symbol']]
    paginated_coins = filtered_coins[(page-1)*per_page : page*per_page]
    
    return jsonify({
        'coins': paginated_coins,
        'current_page': page,
        'total_pages': len(filtered_coins) // per_page + 1
    })

@app.route('/get_coin_details/<symbol>')
def get_coin_details(symbol):
    response = requests.get(f'https://data-api.binance.vision/api/v3/ticker/24hr?symbol={symbol}')
    if response.status_code != 200:
        return jsonify({'error': 'Coin not found'}), 404
    
    coin_data = response.json()
    simplified_data = {
        'symbol': coin_data['symbol'],
        'lastPrice': float(coin_data['lastPrice']),
        'priceChange': float(coin_data['priceChange']),
        'priceChangePercent': float(coin_data['priceChangePercent']),
        'highPrice': float(coin_data['highPrice']),
        'lowPrice': float(coin_data['lowPrice']),
        'volume': float(coin_data['volume']),
        'quoteVolume': float(coin_data['quoteVolume'])
    }
    return jsonify(simplified_data)

@app.route('/get_coin_history/<symbol>')
def get_coin_history(symbol):
    response = requests.get(
        f'https://data-api.binance.vision/api/v3/klines',
        params={'symbol': symbol, 'interval': '5m', 'limit': 24}  # Last 24 periods
    )
    if response.status_code != 200:
        return jsonify({'error': 'History not found'}), 404
    
    raw_data = response.json()
    formatted_data = [{
        'time': entry[0],
        'open': float(entry[1]),
        'high': float(entry[2]),
        'low': float(entry[3]),
        'close': float(entry[4]),
        'volume': float(entry[5])
    } for entry in raw_data]
    
    return jsonify(formatted_data)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not os.path.exists(app.config['UPLOAD_FOLDER']):
            os.makedirs(app.config['UPLOAD_FOLDER'])
    app.run(debug=True)