from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from keras.models import load_model
from flask_migrate import Migrate
from flask_wtf import FlaskForm
from wtforms import IntegerField, SelectField, FloatField
from wtforms.validators import DataRequired
import numpy as np
from sklearn.preprocessing import MinMaxScaler
from flask_cli import FlaskCLI
from keras.preprocessing.sequence import pad_sequences
# Initialize Flask application
app = Flask(__name__)
app.secret_key = 'AA#33#aa'  # Replace with a strong secret key

# Configure the database
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://Abhi:12345@localhost/NIDS'
db = SQLAlchemy(app)

# Initialize Flask-Migrate
migrate = Migrate(app, db)
# User model definition
class User(db.Model):
    # If you have a different primary key or no id column, you can define it here
    username = db.Column(db.String(80), primary_key=True)  # Example using 'username' as primary key
    password = db.Column(db.String(512), nullable=False)
    name = db.Column(db.String(80))
    email = db.Column(db.String(120))
    phone = db.Column(db.String(15))

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

# Function to check if the user is logged in
def is_logged_in():
    return 'username' in session

# Home route for login/signup
@app.route('/', methods=['GET', 'POST'])
def home():
    print("Accessed home route")  # Debug statement

    if is_logged_in():
        return redirect(url_for('intrusion_detection'))

    if request.method == 'POST':
        action = request.form.get('action')

        print(action)  # Debug statement

        if action == 'Sign In':
            username = request.form.get('username')
            password = request.form.get('password')
            user = User.query.filter_by(username=username).first()
            if user and user.check_password(password):
                session['username'] = username
                flash('Successfully logged in!', 'success')
                return redirect(url_for('intrusion_detection'))
            else:
                flash('Invalid username or password.', 'danger')

    return render_template('index.html', logged_in=is_logged_in())

# Logout route
@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('Logged out successfully!', 'info')
    return redirect(url_for('home'))

class PredictionForm(FlaskForm):
    protocol_type_choices = [('tcp', 'TCP'), ('udp', 'UDP'), ('icmp', 'ICMP')]
    service_choices = [('http', 'HTTP'), ('ftp', 'FTP'), ('smtp', 'SMTP')]
    flag_choices = [('SF', 'SF'), ('S0', 'S0'), ('REJ', 'REJ')]
    
    duration = IntegerField('Duration', validators=[DataRequired()])
    protocol_type = SelectField('Protocol Type', choices=protocol_type_choices, validators=[DataRequired()])
    service = SelectField('Service', choices=service_choices, validators=[DataRequired()])
    flag = SelectField('Flag', choices=flag_choices, validators=[DataRequired()])
    src_bytes = IntegerField('Source Bytes', validators=[DataRequired()])
    dst_bytes = IntegerField('Destination Bytes', validators=[DataRequired()])
    hot = IntegerField('Hot', validators=[DataRequired()])
    logged_in = IntegerField('Logged in', validators=[DataRequired()])
    count = IntegerField('Count', validators=[DataRequired()])
    srv_count = IntegerField('Srv_count', validators=[DataRequired()])
    srv_diff_host_rate = FloatField('Srv_diff_host_rate', validators=[DataRequired()])
    dst_host_count = IntegerField('Dst_host_count', validators=[DataRequired()])
    dst_host_srv_count = IntegerField('Dst_host_srv_count', validators=[DataRequired()])
    dst_host_samea_srv_rate =   FloatField('Dst_host_same_srv_rate', validators=[DataRequired()])
    dst_host_diff_srv_rate =  FloatField('Dst_host_diff_srv_rate', validators=[DataRequired()])
    dst_host_same_src_port_rate =  FloatField('Dst_host_same_src_port_rate', validators=[DataRequired()])
    dst_host_same_srv_host_rate =  FloatField('Dst_host_same_srv_host_rate', validators=[DataRequired()])

# Load your trained ML model
# Replace 'your_model_path' with the actual path to your trained model file
cnn_lstm_model = load_model('/Users/abhaydhek/flaskapp/cnn_lstm_model.keras')
# Intrusion Detection route and function
@app.route('/intrusion_detection', methods=['GET', 'POST'])


@app.route('/intrusion_detection', methods=['GET', 'POST'])
def intrusion_detection():
    if not is_logged_in():
        flash('You need to login first!', 'warning')
        return redirect(url_for('home'))

    form = PredictionForm()

    result = None  # Initialize result variable
    
    if request.method == 'POST':
        print("hi")
        # Get the input data from the form
        duration = float(form.duration.data)
        protocol_type = form.protocol_type.data
        service = form.service.data
        flag = form.flag.data
        src_bytes = float(form.src_bytes.data)
        dst_bytes = float(form.dst_bytes.data)
        hot = float(form.hot.data)  
        logged_in = int(form.logged_in.data)
        count = int(form.count.data)
        srv_count = int(form.srv_count.data)
        srv_diff_host_rate = float(form.srv_diff_host_rate.data)
        dst_host_count = int(form.dst_host_count.data)
        dst_host_srv_count = int(form.dst_host_srv_count.data)
        dst_host_samea_srv_rate = float(form.dst_host_samea_srv_rate.data)
        dst_host_diff_srv_rate = float(form.dst_host_diff_srv_rate.data)
        dst_host_same_src_port_rate = float(form.dst_host_same_src_port_rate.data)
        dst_host_same_srv_host_rate = float(form.dst_host_same_srv_host_rate.data)

        # One-Hot Encoding
        protocol_type_encoded = [1 if protocol_type == 'tcp' else 0, 1 if protocol_type == 'udp' else 0, 1 if protocol_type == 'icmp' else 0]
        service_encoded = [1 if service == 'http' else 0, 1 if service == 'ftp' else 0, 1 if service == 'smtp' else 0]
        flag_encoded = [1 if flag == 'SF' else 0, 1 if flag == 'S0' else 0, 1 if flag == 'REJ' else 0]

        # Reshape one-hot encoded arrays
        protocol_type_encoded = np.array(protocol_type_encoded).reshape(1, -1)
        service_encoded = np.array(service_encoded).reshape(1, -1)
        flag_encoded = np.array(flag_encoded).reshape(1, -1)

        # Feature Scaling
        numerical_features = [duration, src_bytes, dst_bytes, hot, logged_in, count, srv_count, srv_diff_host_rate, dst_host_count, dst_host_srv_count, dst_host_samea_srv_rate, dst_host_diff_srv_rate, dst_host_same_src_port_rate, dst_host_same_srv_host_rate]
        scaler = MinMaxScaler(feature_range=(0, 1))
        numerical_features_scaled = scaler.fit_transform(np.array(numerical_features).reshape(1, -1))

        # Concatenate features
        feature_vector = np.concatenate([numerical_features_scaled, protocol_type_encoded, service_encoded, flag_encoded], axis=1)

        

        # Convert feature vector to the format expected by your ML model
        feature_vector = np.array(feature_vector).reshape(1, -1)

        # Reshape for CNN+LSTM model
        feature_vector = np.reshape(feature_vector, (feature_vector.shape[0], feature_vector.shape[1], 1))

        feature_vector = pad_sequences(feature_vector, maxlen=80, padding='post', truncating='post')
        attack_probability = cnn_lstm_model.predict(feature_vector)[0][1]
        # Set a threshold for prediction
        threshold = 0.5
        result = "Attack Detected" if attack_probability > threshold else "No Attack Detected"

    return render_template('intrusion_detection.html', form=form, result=result)


@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username_login')
    password = request.form.get('password_login')
    user = User.query.filter_by(username=username).first()
    if user and user.check_password(password):
        session['username'] = username
        flash('Successfully logged in!', 'success')
        return redirect(url_for('intrusion_detection'))
    else:
        flash('Invalid username or password.', 'danger')

    return render_template('index.html', logged_in=is_logged_in())

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        name = request.form.get('name')
        email = request.form.get('email')
        phone = request.form.get('phone')

        user = User.query.filter_by(username=username).first()
        if user:
            flash('Username already exists. Please choose a different username.', 'warning')
            print("Username already exists. Redirecting to home.")
            return redirect(url_for('home'))
        else:
            new_user = User(username=username, name=name, email=email, phone=phone)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            session['username'] = username
            flash('Account created successfully!', 'success')
            print("Account created successfully. Redirecting to intrusion detection.")
            return redirect(url_for('intrusion_detection'))

    return render_template('index.html', logged_in=is_logged_in())

@app.route('/predict', methods=['POST'])
def predict():
    try:
        if 'result' in session:
            result = session['result']
            # Clear the result from the session after displaying it
            session.pop('result', None)
            return render_template('intrusion_detection.html', result=result)
        else:
            flash('Prediction result not found. Please submit the intrusion detection form first.', 'warning')
            return render_template('intrusion_detection.html', result=None)
    except Exception as e:
        flash(f'Error getting prediction result: {str(e)}', 'danger')
        return render_template('intrusion_detection.html', result=None)

def create_tables():
    with app.app_context():
        db.create_all()

if __name__ == '__main__':
    create_tables()
    FlaskCLI(app)   
    app.run(debug=True) 