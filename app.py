from flask import Flask, render_template, request, redirect, url_for, flash, session, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import hashlib
import os
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///healthcare.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Email Configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'aryanteki03@gmail.com')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', 'svet kysu kwtz tjgu')  # Replace with your App Password
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_USERNAME', 'aryanteki03@gmail.com')

# Initialize extensions
db = SQLAlchemy(app)
mail = Mail(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Generate encryption key
key = Fernet.generate_key()
cipher_suite = Fernet(key)

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'doctor' or 'patient'
    specialization = db.Column(db.String(100))  # For doctors
    phone = db.Column(db.String(20))
    address = db.Column(db.String(200))

class Appointment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    doctor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    patient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date = db.Column(db.DateTime, nullable=False)
    symptoms = db.Column(db.Text)
    status = db.Column(db.String(20), default='pending')
    report_hash = db.Column(db.String(64))

class MedicalReport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    appointment_id = db.Column(db.Integer, db.ForeignKey('appointment.id'), nullable=False)
    content = db.Column(db.LargeBinary, nullable=False)
    hash_value = db.Column(db.String(64), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Helper Functions
def generate_hash(data):
    return hashlib.sha256(data.encode()).hexdigest()

def encrypt_data(data):
    return cipher_suite.encrypt(data.encode())

def decrypt_data(encrypted_data):
    return cipher_suite.decrypt(encrypted_data).decode()

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        name = request.form.get('name')
        role = request.form.get('role')
        specialization = request.form.get('specialization')
        phone = request.form.get('phone')
        address = request.form.get('address')

        if User.query.filter_by(email=email).first():
            flash('Email already registered!')
            return redirect(url_for('register'))

        user = User(
            email=email,
            password=generate_password_hash(password),
            name=name,
            role=role,
            specialization=specialization,
            phone=phone,
            address=address
        )
        db.session.add(user)
        db.session.commit()
        flash('Registration successful!')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            if user.role == 'doctor':
                return redirect(url_for('doctor_dashboard'))
            else:
                return redirect(url_for('patient_dashboard'))
        else:
            flash('Invalid email or password!')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/doctor/dashboard')
@login_required
def doctor_dashboard():
    if current_user.role != 'doctor':
        return redirect(url_for('index'))
    
    # Get all appointments for the current doctor
    appointments = Appointment.query.filter_by(doctor_id=current_user.id).all()
    
    # Create a list of appointments with patient information
    appointments_with_patients = []
    for appointment in appointments:
        patient = User.query.get(appointment.patient_id)
        appointments_with_patients.append({
            'appointment': appointment,
            'patient': patient
        })
    
    return render_template('doctor_dashboard.html', appointments=appointments_with_patients)

@app.route('/patient/dashboard')
@login_required
def patient_dashboard():
    if current_user.role != 'patient':
        return redirect(url_for('index'))
    
    appointments = Appointment.query.filter_by(patient_id=current_user.id).all()
    # Create a list of appointments with doctor information
    appointments_with_doctors = []
    for appointment in appointments:
        doctor = User.query.get(appointment.doctor_id)
        appointments_with_doctors.append({
            'appointment': appointment,
            'doctor': doctor
        })
    
    return render_template('patient_dashboard.html', appointments=appointments_with_doctors)

@app.route('/book_appointment', methods=['GET', 'POST'])
@login_required
def book_appointment():
    if current_user.role != 'patient':
        return redirect(url_for('index'))

    if request.method == 'POST':
        doctor_id = request.form.get('doctor_id')
        date = datetime.strptime(request.form.get('date'), '%Y-%m-%d')
        symptoms = request.form.get('symptoms')

        appointment = Appointment(
            doctor_id=doctor_id,
            patient_id=current_user.id,
            date=date,
            symptoms=symptoms
        )
        db.session.add(appointment)
        db.session.commit()
        flash('Appointment booked successfully!')
        return redirect(url_for('patient_dashboard'))

    doctors = User.query.filter_by(role='doctor').all()
    return render_template('book_appointment.html', doctors=doctors)

@app.route('/upload_report/<int:appointment_id>', methods=['GET', 'POST'])
@login_required
def upload_report(appointment_id):
    if current_user.role != 'doctor':
        return redirect(url_for('index'))

    appointment = Appointment.query.get_or_404(appointment_id)
    if appointment.doctor_id != current_user.id:
        return redirect(url_for('index'))

    # Get patient information
    patient = User.query.get(appointment.patient_id)

    if request.method == 'POST':
        report_content = request.form.get('report')
        encrypted_content = encrypt_data(report_content)
        hash_value = generate_hash(report_content)

        report = MedicalReport(
            appointment_id=appointment_id,
            content=encrypted_content,
            hash_value=hash_value
        )
        db.session.add(report)
        appointment.report_hash = hash_value
        db.session.commit()

        try:
            # Send email to patient
            msg = Message(
                'Your Medical Report is Ready',
                recipients=[patient.email]
            )
            msg.body = f'''Dear {patient.name},

Your medical report from your appointment on {appointment.date.strftime('%Y-%m-%d')} is now ready.

You can access your report by logging into your account and using the following hash value:
{hash_value}

Best regards,
Dr. {current_user.name}'''

            mail.send(msg)
            flash('Report uploaded and email sent successfully!', 'success')
        except Exception as e:
            flash('Report uploaded successfully, but email could not be sent.', 'warning')
            app.logger.error(f"Email sending failed: {str(e)}")
            # You might want to implement a retry mechanism or queue the email for later

        return redirect(url_for('doctor_dashboard'))

    return render_template('upload_report.html', appointment=appointment, patient=patient)

@app.route('/view_report/<int:appointment_id>')
@login_required
def view_report(appointment_id):
    appointment = Appointment.query.get_or_404(appointment_id)
    if current_user.role == 'patient' and appointment.patient_id != current_user.id:
        return redirect(url_for('index'))
    if current_user.role == 'doctor' and appointment.doctor_id != current_user.id:
        return redirect(url_for('index'))

    report = MedicalReport.query.filter_by(appointment_id=appointment_id).first()
    if report:
        decrypted_content = decrypt_data(report.content)
        return render_template('view_report.html', report=decrypted_content, hash_value=report.hash_value)
    
    flash('Report not found!')
    return redirect(url_for('index'))

@app.route('/download_report', methods=['GET', 'POST'])
@login_required
def download_report():
    if request.method == 'POST':
        appointment_id = request.form.get('appointment_id')
        hash1 = request.form.get('hash1')
        hash2 = request.form.get('hash2')
        
        # Verify the appointment belongs to the current user
        appointment = Appointment.query.get_or_404(appointment_id)
        if appointment.patient_id != current_user.id:
            flash('Unauthorized access to this report', 'danger')
            return redirect(url_for('patient_dashboard'))
        
        # Get the medical report
        report = MedicalReport.query.filter_by(appointment_id=appointment_id).first()
        if not report:
            flash('Report not found', 'danger')
            return redirect(url_for('patient_dashboard'))
        
        # Verify hash values
        if report.hash1 != hash1 or report.hash2 != hash2:
            flash('Invalid hash values. Please check the values provided by your doctor.', 'danger')
            return redirect(url_for('download_report'))
        
        # Decrypt the report content
        decrypted_content = decrypt_data(report.content)
        
        # Create a response with the decrypted content
        response = make_response(decrypted_content)
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'attachment; filename=medical_report_{appointment_id}.pdf'
        
        return response
    
    return render_template('download_report.html')

@app.route('/complete_appointment/<int:appointment_id>', methods=['POST'])
@login_required
def complete_appointment(appointment_id):
    if current_user.role != 'doctor':
        return redirect(url_for('index'))
    
    appointment = Appointment.query.get_or_404(appointment_id)
    
    # Verify the appointment belongs to the current doctor
    if appointment.doctor_id != current_user.id:
        flash('Unauthorized access to this appointment', 'danger')
        return redirect(url_for('doctor_dashboard'))
    
    # Update appointment status
    appointment.status = 'completed'
    db.session.commit()
    
    flash('Appointment marked as completed successfully!', 'success')
    return redirect(url_for('doctor_dashboard'))

# Initialize database
def init_db():
    with app.app_context():
        db.create_all()
        print("Database tables created successfully!")

if __name__ == '__main__':
    init_db()
    app.run(debug=True) 