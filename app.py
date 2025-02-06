from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, login_required, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

# Initialize Flask app
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'  # Database file
app.config['SECRET_KEY'] = 'your_secret_key'  # Secret key for security
db = SQLAlchemy(app)

# Initialize Login Manager
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # Route for login page

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)  # Admin flag
    predictions = db.relationship('Prediction', backref='user', lazy=True)

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def set_password(self, password):
        self.password = generate_password_hash(password)

class Match(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    team_1 = db.Column(db.String(100), nullable=False)
    team_2 = db.Column(db.String(100), nullable=False)
    date = db.Column(db.DateTime, nullable=False)
    result = db.Column(db.String(10), nullable=True)  # Match result

class Prediction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    match_id = db.Column(db.Integer, db.ForeignKey('match.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    prediction = db.Column(db.String(10), nullable=False)  # win, draw, loss

# Load user for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Homepage Route
@app.route('/')
def home():
    return render_template('index.html')

# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password', 'danger')
    return render_template('login.html')

# Logout Route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('home'))

# Register Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        # Check if username or email already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists!', 'danger')
            return redirect(url_for('register'))
        if User.query.filter_by(email=email).first():
            flash('Email already exists!', 'danger')
            return redirect(url_for('register'))

        # Create new user
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

# Profile Route
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        # Update profile details
        current_user.username = request.form.get('username')
        current_user.email = request.form.get('email')
        new_password = request.form.get('password')
        if new_password:
            current_user.set_password(new_password)
        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))

    return render_template('profile.html', user=current_user)

# Predict Route
@app.route('/predict', methods=['GET', 'POST'])
@login_required
def predict():
    if request.method == 'POST':
        # Get selected matches and predictions
        selected_matches = request.form.getlist('selected_matches')  # List of selected match IDs
        for match_id in selected_matches:
            prediction_value = request.form.get(f'prediction_{match_id}')
            if prediction_value:
                # Save the prediction to the database
                prediction = Prediction(
                    match_id=match_id,
                    user_id=current_user.id,
                    prediction=prediction_value
                )
                db.session.add(prediction)
        db.session.commit()
        flash('Predictions submitted successfully!', 'success')
        return redirect(url_for('predict'))

    # Fetch all matches for the form
    matches = Match.query.order_by(Match.date).all()
    return render_template('predict.html', matches=matches)

# Results Route
@app.route('/results')
@login_required
def results():
    # Fetch the current user's predictions
    user_predictions = Prediction.query.filter_by(user_id=current_user.id).all()
    
    # Create a dictionary to store match details and predictions
    user_results = {}
    for prediction in user_predictions:
        match = Match.query.get(prediction.match_id)
        match_name = f"{match.team_1} vs {match.team_2} ({match.date.strftime('%Y-%m-%d %H:%M')})"
        user_results[match_name] = prediction.prediction
    
    return render_template('results.html', user_results=user_results)

# Admin Matches Route
@app.route('/admin/matches', methods=['GET', 'POST'])
@login_required
def manage_matches():
    if not current_user.is_admin:
        flash("Access denied!", "danger")
        return redirect(url_for('home'))

    if request.method == 'POST':
        Match.query.delete()
        db.session.commit()
        
        for i in range(1, 11):  # Allow admin to enter up to 10 matches
            team_1 = request.form.get(f'team_1_{i}')
            team_2 = request.form.get(f'team_2_{i}')
            date_str = request.form.get(f'date_{i}')
            
            if team_1 and team_2 and date_str:
                date = datetime.strptime(date_str, '%Y-%m-%d %H:%M')
                match = Match(team_1=team_1, team_2=team_2, date=date)
                db.session.add(match)
        
        db.session.commit()
        flash("Matches updated successfully!", "success")
        return redirect(url_for('manage_matches'))

    matches = Match.query.order_by(Match.date).all()
    return render_template('admin_matches.html', matches=matches)

# Admin Results Route
@app.route('/admin/results', methods=['GET', 'POST'])
@login_required
def enter_results():
    if not current_user.is_admin:
        flash("Access denied!", "danger")
        return redirect(url_for('home'))
    
    matches = Match.query.order_by(Match.date).all()
    
    if request.method == 'POST':
        for match in matches:
            result = request.form.get(f'result_{match.id}')
            if result:
                match.result = result
        db.session.commit()
        flash("Results updated successfully!", "success")
        return redirect(url_for('enter_results'))
    
    return render_template('admin_results.html', matches=matches)

# Run the app
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create database tables
    app.run(debug=True)  # Run the app in debug mode