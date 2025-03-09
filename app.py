import io
import os
import csv
import math
import webbrowser
import mysql.connector
from flask import Flask, app, flash, session, make_response, Response
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from datetime import datetime, date
from flask import render_template, request, redirect, url_for, jsonify
from sqlalchemy import or_
from threading import Timer
from fpdf import FPDF
from flask_mail import Mail, Message
from functools import wraps
from io import StringIO
from werkzeug.security import generate_password_hash, check_password_hash
from flask import session, url_for
from flask import Flask, flash



# Database connection function
def get_db_connection():
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="brayookk7",
        database="livestockmanagement"
    )
    return conn

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:brayookk7@localhost/livestockmanagement'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'supersecretkey'
app.secret_key = 'your_secret_key'  # Needed for flash messages
db = SQLAlchemy(app)

# Configure Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.yourmailserver.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'your-email@example.com'
app.config['MAIL_PASSWORD'] = 'your-password'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
mail = Mail(app)

# Example of sending a reset password email
def send_reset_email(user):
    token = user.get_reset_token()  # Token generation logic goes here
    msg = Message('Password Reset Request', sender='noreply@yourapp.com', recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link:
    {url_for('reset_password', token=token, _external=True)}
    If you did not make this request then simply ignore this email.
    '''
    mail.send(msg)


migrate = Migrate(app, db)

def roles_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = User.query.filter_by(UserID=session.get('user_id')).first() # Assuming you store user_id in session
            if not user or (user.Role not in roles and user.Role != 'admin'):
                flash('You do not have permission to access this page', 'error')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator


class User(db.Model):
    UserID = db.Column(db.Integer, primary_key=True)
    Username = db.Column(db.String(80), unique=True, nullable=False)
    Email = db.Column(db.String(120), unique=True, nullable=False)
    Password = db.Column(db.String(120), nullable=False)
    Role = db.Column(db.String(50), nullable=False, default="user")

class birthidentificationrecord(db.Model):
    AnimalID = db.Column(db.String(10), primary_key=True)
    Species = db.Column(db.String(80), nullable=False)
    Breed = db.Column(db.String(80), nullable=False)
    Sex = db.Column(db.String(80), nullable=False)
    DamNumber = db.Column(db.String(80), nullable=False)
    SireNumber = db.Column(db.String(80), nullable=False)
    DateOfBirth = db.Column(db.Date, nullable=False)
    DateAcquired = db.Column(db.Date, nullable=True, default=None)
    BirthWeight = db.Column(db.Float, nullable=False)
    Color = db.Column(db.String(80), nullable=False)


class Calf(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    calf_name = db.Column(db.String(255), nullable=False)
    calf_birth_date = db.Column(db.Date, nullable=False)
    calf_breed = db.Column(db.String(255), nullable=False)
    calf_weight = db.Column(db.Float, nullable=False)
    dam_name = db.Column(db.String(255), nullable=False)  # Dam is the mother cow's name
    sire_name = db.Column(db.String(255), nullable=False)  # Sire is the father bull's name

class report(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    breed = db.Column(db.String(80), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    sex = db.Column(db.String(80), nullable=False)

class milkingrecord(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    animal_id = db.Column(db.Integer, nullable=False)
    date = db.Column(db.Date, nullable=False)
    morning_milk = db.Column(db.Float, nullable=False)
    evening_milk = db.Column(db.Float, nullable=False)
    total_milk = db.Column(db.Float, nullable=False)
    notes = db.Column(db.Text, nullable=True)

    def __init__(self, animal_id, date, morning_milk, evening_milk, total_milk, notes):
        self.animal_id = animal_id
        self.date = date
        self.morning_milk = morning_milk
        self.evening_milk = evening_milk
        self.total_milk = total_milk
        self.notes = notes

db = SQLAlchemy()

class AuditTrail(db.Model):
    __tablename__ = 'audit_trail'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.UserID', ondelete="SET NULL"), nullable=True)
    action = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp())

    # Relationship to User Model
    user = db.relationship('User', backref='audit_logs')

    def __init__(self, user_id, action):
        self.user_id = user_id
        self.action = action

    def save(self):
        db.session.add(self)
        db.session.commit()

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "action": self.action,
            "timestamp": self.timestamp
        }

def log_action(user_id, action):
    new_log = AuditTrail(user_id=user_id, action=action)
    new_log.save()


def record_audit_log(user_id, action):
    if not user_id:
        return  # Don't log if no user is logged in

    connection = mysql.connector.connect(user='root', password='brayookk7', database='livestockmanagement')
    cursor = connection.cursor()

    query = "INSERT INTO audit_trail (UserID, action, timestamp) VALUES (%s, %s, NOW())"
    cursor.execute(query, (user_id, action))

    connection.commit()
    cursor.close()
    connection.close()


def get_audit_logs():
    connection = mysql.connector.connect(user='root', password='brayookk7', database='livestockmanagement')
    cursor = connection.cursor(dictionary=True)

    # Fetch logs with user information
    cursor.execute("""
        SELECT user.Username, audit_trail.action, audit_trail.timestamp 
        FROM audit_trail
        LEFT JOIN user ON audit_trail.UserID = user.UserID
        ORDER BY audit_trail.timestamp DESC
    """)

    logs = cursor.fetchall()
    cursor.close()
    connection.close()
    return logs




# Routes
@app.route('/')
def home():
    #cattle = birthidentificationrecord.query.all()
    return redirect(url_for('login'))

def open_browser():
    """Open the default web browser after the server starts."""
    if not app.debug or os.environ.get("WERKZEUG_RUN_MAIN") == "true":
        webbrowser.open_new("http://127.0.0.1:5000")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['Username']
        password = request.form['Password']

        # Query user from the database
        user = User.query.filter_by(Username=username).first()

        # Check if user exists and verify password
        if user and check_password_hash(user.Password, password):
            session['user_id'] = user.UserID
            session['user_role'] = user.Role

            # Record audit log for login
            action = f"User {username} logged in."
            record_audit_log(user.UserID, action)

            return redirect(url_for('dashboard'))  # Redirect to dashboard upon successful login
        else:
            return render_template('login.html', error="Invalid username or password")

    return render_template('login.html')



@app.route('/admin', methods=['GET'])
def admin():
    try:
        # Connect to the database
        conn = mysql.connector.connect(
            host="localhost",
            user="root",
            password="brayookk7",
            database="livestockmanagement"
        )
        cursor = conn.cursor(dictionary=True)

        # Fetch audit logs with user information
        cursor.execute("""
               SELECT user.Username AS User, audit_trail.action AS Action, 
                      DATE_FORMAT(audit_trail.timestamp, '%Y-%m-%d %H:%i:%s') AS Timestamp
               FROM audit_trail
               LEFT JOIN user ON audit_trail.UserID = user.UserID
               ORDER BY audit_trail.timestamp DESC
           """)

        audit_logs = cursor.fetchall()


        cursor.execute("SELECT * FROM section")
        sections = cursor.fetchall()


        # Fetch data for dashboard metrics
        cursor.execute("SELECT COUNT(*) AS total FROM birthidentificationrecord")
        total_animals = cursor.fetchone()
        total_animals = total_animals["total"] if total_animals else 0

        cursor.execute("SELECT COUNT(*) AS recent FROM birthidentificationrecord WHERE DateOfBirth >= DATE_SUB(NOW(), INTERVAL 1 MONTH)")
        recent_births = cursor.fetchone()
        recent_births = recent_births["recent"] if recent_births else 0

        cursor.execute("SELECT COALESCE(SUM(QuantityProduced), 0) AS milk_data FROM milkproductionrecord WHERE MONTH(ProductionDate) = MONTH(CURDATE())")
        milk_data = cursor.fetchone()
        milk_data = milk_data["milk_data"] if milk_data else 0

        cursor.execute("SELECT COALESCE(SUM(Amount), 0) AS sales_data FROM sales WHERE MONTH(SaleDate) = MONTH(CURDATE())")
        sales_data = cursor.fetchone()
        sales_data = sales_data["sales_data"] if sales_data else 0

        cursor.close()
        conn.close()

        return render_template('admin.html',
            total_animals=total_animals,
            recent_births=recent_births,
            milk_data=milk_data,
            sales_data=sales_data,
            sections=sections,
            audit_logs=audit_logs
        )

    except mysql.connector.Error as err:
        return f"Database error: {err}"


@app.route('/add_section', methods=['POST'])
def add_section():
    try:
        conn = mysql.connector.connect(
            host="localhost",
            user="root",
            password="brayookk7",
            database="livestockmanagement"
        )
        cursor = conn.cursor()

        section_name = request.form.get('section_name')
        section_manager = request.form.get('section_manager')
        description = request.form.get('description')

        cursor.execute(
            "INSERT INTO section (SectionName, SectionManager, Description) VALUES (%s, %s, %s)",
            (section_name, section_manager, description)
        )
        conn.commit()

        cursor.close()
        conn.close()

        return redirect(url_for('admin'))

    except mysql.connector.Error as err:
        return f"Database error: {err}"

@app.route('/view_users')
@roles_required('admin')  # Ensure only admin can access
def view_users():
    users = User.query.all()  # Fetch all users from the database
    return render_template('view_users.html', users=users)

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@roles_required('admin')  # Only admins can access this
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        user.username = request.form['username']
        user.email = request.form['email']
        user.Role = request.form['role']
        db.session.commit()
        flash("User information updated successfully", "success")
        return redirect(url_for('view_users'))
    return render_template('edit_user.html', user=user)

#@app.route('/delete_user/<int:user_id>', methods=['POST'])
#@roles_required('admin')  # Only admins can access this
#def delete_user(user_id):
#    user = User.query.get_or_404(user_id)
#    db.session.delete(user)
#    db.session.commit()
 #   flash("User deleted successfully", "success")
#    return redirect(url_for('view_users'))


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        # Logic to verify if the email exists in the database
        user = User.query.filter_by(email=email).first()

        if user:
            # Here, you'd send an email with a reset link (use Flask-Mail or similar)
            flash('An email has been sent to reset your password', 'success')
            return redirect(url_for('login'))
        else:
            flash('No account found with that email address', 'error')

    return render_template('forgot_password.html')


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    # Logic to verify the token (if you're using token-based password reset)
    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if new_password == confirm_password:
            # Update the user's password in the database
            # Assume `user` is fetched based on the token
            User.password = new_password  # Make sure to hash the password
            db.session.commit()
            flash('Your password has been updated', 'success')
            return redirect(url_for('login'))
        else:
            flash('Passwords do not match', 'error')

    return render_template('reset_password.html')


@app.route('/register', methods=['GET', 'POST'])
#@roles_required('admin')
def register():
    VALID_ROLES = {'admin', 'user', 'records_manager', 'department_head', 'livestock_manager'}

    if request.method == 'POST':
        username = request.form['Username']
        email = request.form['Email']
        password = request.form['Password']
        role = request.form.get('Role', 'user')

        # Validate role
        if role not in VALID_ROLES:
            return render_template('register.html', error="Invalid role selected")

        # Check if the username or email already exists
        existing_user = User.query.filter(
            (User.Username == username) | (User.Email == email)
        ).first()

        if existing_user:
            return render_template('register.html', error="Username or Email already exists")

        # Create a new user
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')  # Hash the password
        new_user = User(Username=username, Email=email, Password=hashed_password, Role=role)

        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('login'))  # Redirect to login after successful registration

    return render_template('register.html')


@app.route('/dashboard')
def dashboard():
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="brayookk7",
        database="livestockmanagement"
    )
    cursor = conn.cursor()

    total_cows= 0

    try:
        # Fetch key metrics for the dashboard
        cursor.execute("SELECT COUNT(*) FROM birthidentificationrecord")
        total_cows = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM birthidentificationrecord WHERE CAST(DateOfBirth AS DATE) >= DATE_SUB(CURDATE(), INTERVAL 1 MONTH)")
        recent_births = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM mortalityrecord")
        total_mortality = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM milkproductionrecord")
        milk_data = cursor.fetchone()[0]

        cursor.execute("SELECT COALESCE(SUM(QuantityProduced), 0) FROM milkproductionrecord WHERE ProductionDate = CURDATE()")
        milk_data = cursor.fetchone()[0] or 0

        cursor.execute("SELECT COUNT(*) FROM healthvaccinationrecord")
        total_health_records = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM breedingrecordnatural")
        total_breeding_records = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM sales")
        total_sales = cursor.fetchone()[0]

        cursor.execute("SELECT SUM(Amount) FROM sales")
        total_sales_revenue = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM breedingschedule")
        total_breeding_schedules = cursor.fetchone()[0]

        # Fetch latest activities for timeline display
        cursor.execute("""
            SELECT ProductionDate, SUM(QuantityProduced) 
            FROM milkproductionrecord 
            WHERE ProductionDate >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)
            GROUP BY ProductionDate
            ORDER BY ProductionDate ASC
        """)
        milk_data = cursor.fetchall()

        # Prepare data for Chart.js
        milk_production_data = {
            "labels": [str(row[0]) for row in milk_data],  # Dates
            "values": [row[1] for row in milk_data],  # Production amounts
        }

        # Fetch latest routine activities **before closing the connection**
        cursor.execute("""
            SELECT AnimalID, RecordID, ActivityDate 
            FROM routinerecords 
            ORDER BY ActivityDate DESC 
            LIMIT 5
        """)
        recent_activities = cursor.fetchall()

    except Exception as e:
        print(f"Error: {e}")
        recent_activities = []
        total_cows = recent_births = milk_data = total_breeding_records = 0
        total_sales = total_sales_revenue = total_health_records = total_mortality = 0
        milk_data = 0
        total_breeding_schedules = 0
        milk_production_data = {"labels": [], "values": []}  # Empty data in case of error

    finally:
        cursor.close()
        conn.close()

    # Render the dashboard template
    return render_template(
        'dashboard.html',
        total_cows=total_cows,
        recent_births=recent_births,
        total_mortality=total_mortality,
        milk_data=milk_data,
        milk_production_data=milk_production_data,  # Use the correct variable
        total_health_records=total_health_records,
        total_breeding_records=total_breeding_records,
        total_sales=total_sales,
        total_sales_revenue=total_sales_revenue,
        recent_activities=recent_activities,
        total_breeding_schedules=total_breeding_schedules
    )


@app.route('/register_cow', methods=['GET', 'POST'])
def register_cow():
    if request.method == 'POST':
        try:
            animalid = request.form.get('AnimalId')
            species = request.form.get('species')
            breed = request.form.get('breed')
            sex = request.form.get('sex')
            dam_number = request.form.get('dam_number')
            sire_number = request.form.get('sire_number')
            date_of_birth = request.form.get('date_of_birth')
            date_acquired = request.form.get('date_acquired') or None
            weight = float(request.form.get('birth_weight') or 0.0)  # Default weight if empty
            color = request.form.get('color')
            user_id = session.get('user_id')  # Get logged-in user ID

            print("Received Data:", animalid, species, breed, sex, dam_number, sire_number, date_of_birth, date_acquired, weight, color)  # Debugging Line

            conn = mysql.connector.connect(
                host="localhost",
                user="root",
                password="brayookk7",
                database="livestockmanagement"
            )
            cursor = conn.cursor()

            # Check if animal already exists
            cursor.execute("SELECT * FROM birthidentificationrecord WHERE AnimalID = %s", (animalid,))
            existing_animal = cursor.fetchone()

            if existing_animal:
                # Update existing record
                cursor.execute("""
                    UPDATE birthidentificationrecord SET 
                        Species=%s, Breed=%s, Sex=%s, DamNumber=%s, SireNumber=%s, 
                        DateOfBirth=%s, DateAcquired=%s, BirthWeight=%s, Color=%s 
                    WHERE AnimalID=%s
                """, (species, breed, sex, dam_number, sire_number, date_of_birth, date_acquired, weight, color, animalid))
                flash("Animal record updated successfully!", "success")
            else:
                # Insert new record
                cursor.execute("""
                    INSERT INTO birthidentificationrecord (AnimalID, Species, Breed, Sex, DamNumber, SireNumber, DateOfBirth, DateAcquired, BirthWeight, Color) 
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (animalid, species, breed, sex, dam_number, sire_number, date_of_birth, date_acquired, weight, color))
                flash("Animal record added successfully!", "success")

            conn.commit()

            # Record the audit log after adding the animal
            action = f"Added animal with tag {animalid}"
            record_audit_log(user_id, action)

            cursor.close()
            conn.close()

        except Exception as e:
            print("Database Error:", str(e))  # Print the error in the terminal
            flash(f"Error: {str(e)}", "danger")

        return redirect(url_for('register_cow'))

    cow_data = birthidentificationrecord.query.all()
    return render_template('register_cow.html', cow_data=cow_data)


@app.route('/breeding_management')
def breeding_management():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch Sire/Dam Pairing Data
    cursor.execute("""
        SELECT SireID, DamID, ServiceDate, ResultCheckDate 
        FROM breedingrecordai
    """)
    pairings = cursor.fetchall()

    conn.close()

    return render_template('breeding_management.html', pairings=pairings)

# Route for Breeding Records Page
@app.route('/breeding_records')
def breeding_records():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch Breeding Records
    cursor.execute("""
        SELECT HerdID, SireID, DamID, DateJoin, DateExit, Reason
        FROM breedingrecordnatural
    """)
    breeding_records = cursor.fetchall()

    conn.close()

    return render_template('breeding_records.html', breeding_records=breeding_records)

# Route for Insemination Records Page
@app.route('/insemination_records')
def insemination_records():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch Insemination Records
    cursor.execute("""
        SELECT SireId, DamId, ServiceDate, ResultCheckDate
        FROM breedingrecordai
    """)
    insemination_records = cursor.fetchall()

    conn.close()

    return render_template('insemination_records.html', insemination_records=insemination_records)

@app.route('/breeding_schedule', methods=['GET', 'POST'])
def breeding_schedule():
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="brayookk7",
        database="livestockmanagement"
    )
    cursor = conn.cursor()

    service_date = None  # Define `service_date` before using it
    user_id = session.get('user_id')  # Get logged-in user ID at the beginning

    if request.method == 'POST':
        sire_id = request.form.get('sire_id')
        dam_id = request.form.get('dam_id')
        service_date = request.form.get('service_date')
        performance_metric = request.form.get('performance_metric')

        query = """
        INSERT INTO breedingschedule (SireID, DamID, ServiceDate, PerformanceMetrics)
        VALUES (%s, %s, %s, %s)
        """
        cursor.execute(query, (sire_id, dam_id, service_date, performance_metric))
        conn.commit()

        if service_date:
            action = f"Added Breeding Schedule with service date {service_date}"
            record_audit_log(user_id, action)

    cursor.execute("SELECT SireID, DamID, ServiceDate, PerformanceMetrics FROM breedingschedule")
    schedule = cursor.fetchall()

    conn.close()
    return render_template('breeding_schedule.html', schedule=schedule)


# Route for Selection Checklist Page
@app.route('/selection_checklist')
def selection_checklist():
    # Static checklist for now, can be extended to fetch dynamic data
    checklist = [
        "Ensure Dam has no reproductive issues.",
        "Check Sire's genetic quality and performance history.",
        "Verify vaccination status of breeding pair.",
        "Ensure optimal weight and health conditions for both animals."
    ]

    return render_template('selection_checklist.html', checklist=checklist)

@app.route('/help', methods=['GET', 'POST'])
def help():
    if request.method == 'POST':
        issue = request.form['issue']
        email = request.form['email']

        return redirect(url_for('help'))
    return render_template('help.html')

@app.route('/submit_help_request', methods=['POST'])
def submit_help_request():
    issue = request.form['issue']
    email = request.form['email']
    # Handle the help request (e.g., save to the database, send an email, etc.)
    return redirect(url_for('help'))

@app.route('/logout')
def logout():
    # Add any logout logic here (e.g., clearing sessions)
    return redirect(url_for('login'))


# Route: Animal Management
@app.route('/cows', methods=['GET', 'POST'])
def cows():
    # Establish the database connection
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="brayookk7",
        database="livestockmanagement"
    )
    cursor = conn.cursor()

    # Initialize variables
    search_term = request.form.get('search_term', '')
    filtered_animals = []
    total_animals = 0
    species_list = []
    breed_list = []

    species = request.form.get('species', '')
    breed = request.form.get('breed', '')

    try:
        # Fetch total count for pagination
        count_query = "SELECT COUNT(*) FROM birthidentificationrecord WHERE 1=1"
        params = []

        if search_term:
            count_query += " AND (AnimalID LIKE %s OR Species LIKE %s)"
            search_value = f"%{search_term}%"
            params.extend([search_value, search_value])

        if species:
            count_query += " AND Species = %s"
            params.append(species)

        if breed:
            count_query += " AND Breed = %s"
            params.append(breed)



        # Fetch paginated records
        query = """SELECT AnimalID, Species, Breed, Sex, DamNumber, SireNumber, DateOfBirth, Birthweight, Color 
                      FROM birthidentificationrecord WHERE 1=1"""
        params = []

        if search_term:
            query += " AND (AnimalID LIKE %s OR Species LIKE %s)"
            search_value = f"%{search_term}%"
            params.extend([search_value, search_value])

        if species:
            query += " AND Species = %s"
            params.append(species)

        if breed:
            query += " AND Breed = %s"
            params.append(breed)


        cursor.execute(query, tuple(params))
        filtered_animals = cursor.fetchall()

    # try:
        # Fetch total animal count
        cursor.execute("SELECT COUNT(*) FROM birthidentificationrecord")
        total_animals = cursor.fetchone()[0]

        # Fetch species and breed for dropdowns
        cursor.execute("SELECT DISTINCT Species FROM birthidentificationrecord")
        species_list = [row[0] for row in cursor.fetchall()]

        cursor.execute("SELECT DISTINCT Breed FROM birthidentificationrecord")
        breed_list = [row[0] for row in cursor.fetchall()]

        # Handle search and filter
        if request.method == 'POST':
            species = request.form.get('species')
            breed = request.form.get('breed')

            query = "SELECT AnimalID, Species, Breed, Sex, DamNumber, SireNumber, DateOfBirth, Birthweight, Color FROM birthidentificationrecord WHERE 1=1"
            params = []

            if search_term:
                query += " AND (AnimalId LIKE %s OR species LIKE %s)"
                search_value = f"%{search_term}%"
                params.extend([search_value, search_value])

            if species:
                query += " AND species = %s"
                params.append(species)

            if breed:
                query += " AND breed = %s"
                params.append(breed)

            cursor.execute(query, tuple(params))
            filtered_animals = cursor.fetchall()

    except Exception as e:
        print(f"Error: {e}")
        filtered_animals = []

    finally:
        cursor.close()
        conn.close()

    return render_template(
        'cows.html',
        total_animals=total_animals,
        species_list=species_list,
        breed_list=breed_list,
        search_term=search_term,
        filtered_animals=filtered_animals,

    )








@app.route('/total_cows')
@roles_required('scientist', 'admin')
def total_cows():
    # Replace with actual logic
    cows = birthidentificationrecord.query.all()

    # Calculate the age for each cow
    for cow in cows:
        if cow.DateOfBirth:  # Ensure DateOfBirth is not NULL
            today = date.today()
            cow.age = today.year - cow.DateOfBirth.year - (
                        (today.month, today.day) < (cow.DateOfBirth.month, cow.DateOfBirth.day))
        else:
            cow.age = 'Unknown'  # Handle cases where DOB is missing

    total_cows = len(cows)
    return render_template('total_cows.html', cows=cows, total_cows=total_cows)

@app.route('/cow_types')
@roles_required('scientist', 'admin')
def cow_types():
    # Replace with actual logic
    cow_types = db.session.query(birthidentificationrecord.breed, db.func.count(birthidentificationrecord.breed)).group_by(birthidentificationrecord.breed).all()
    return render_template('cow_types.html', cow_types=cow_types)

@app.route('/search_cows', methods=['POST'])
@roles_required('scientist', 'admin')
def search_cows():
    search_term = request.form.get('search_term')
    # Replace with actual search logic
    cows = birthidentificationrecord.query.filter(or_(
        birthidentificationrecord.name.ilike(f"%{search_term}%"),
        birthidentificationrecord.breed.ilike(f"%{search_term}%")
    )).all()  # Adjust this filter as needed

    if cows:
        breeds = {}
        for cow in cows:
            if cow.breed in breeds:
                breeds[cow.breed] += 1
            else:
                breeds[cow.breed] = 1

        breed_labels = list(breeds.keys())
        breed_data = list(breeds.values())
    else:
        # If no cows found, set breed_labels and breed_data as empty lists
        breed_labels = []
        breed_data = []

    return render_template('cows.html', cows=cows, breed_labels=breed_labels, breed_data=breed_data, total_cows=len(cows))


@app.route('/calvings')
@roles_required('scientist', 'admin')
def calvings():
    # Retrieve calvings data from the database
    calvings = Calf.query.all()  # Replace with actual data retrieval
    return render_template('calvings.html', calvings=calvings)

@app.route('/milk_production', methods=['GET', 'POST'])
def milk_production():
    # Connect to the database
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="brayookk7",
        database="livestockmanagement"
    )
    cursor = conn.cursor()

    if request.method == 'POST':
        # Get form data
        animal_id = request.form['animal_id']
        quantity = request.form['quantity']
        production_time = request.form['time']
        production_date = request.form['date']

        # Insert milk production record
        cursor.execute("""
                    INSERT INTO milkproductionrecord (AnimalID, QuantityProduced, ProductionTime, ProductionDate)
                    VALUES (%s, %s, %s, %s)
                """, (animal_id, quantity, production_time, production_date))
        conn.commit()

        # Fetch all milk production records
    cursor.execute("SELECT AnimalID, QuantityProduced, ProductionTime, ProductionDate FROM milkproductionrecord")
    milk_data = cursor.fetchall()

    # Fetch available animals for dropdown
    cursor.execute("SELECT AnimalID FROM birthidentificationrecord")
    animals = cursor.fetchall()

    # Prepare chart data
    cursor.execute(
        "SELECT ProductionDate, SUM(QuantityProduced) FROM milkproductionrecord GROUP BY ProductionDate ORDER BY ProductionDate")
    chart_data_raw = cursor.fetchall()
    chart_labels = [row[0].strftime("%Y-%m-%d") for row in chart_data_raw]
    chart_data = [row[1] for row in chart_data_raw]


    return render_template(
    'milk_production.html',
    milk_data=milk_data,
    animals=animals,
    chart_labels=chart_labels,
    chart_data=chart_data
)


@app.route('/search_animal', methods=['GET'])
def search_animal():
    search_term = request.args.get('query', '')

    if not search_term:
        return jsonify([])

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT AnimalID FROM birthidentificationrecord WHERE AnimalID LIKE %s LIMIT 5", (f"%{search_term}%",))
        results = cursor.fetchall()

    return jsonify([row[0] for row in results])

@app.route('/sales', methods=['GET', 'POST'])
def sales():
    # Connect to the database
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="brayookk7",
        database="livestockmanagement"
    )
    cursor = conn.cursor()

    if request.method == 'POST':
        # Add a new sales record
        item = request.form['item']
        description = request.form['description']
        quantity = request.form['quantity']
        amount = request.form['amount']
        sale_date = request.form['sale_date']
        fodder_id = request.form['fodder_id']

        query = """
            INSERT INTO sales (Item, Description, Quantity, Amount, SaleDate, FodderID)
            VALUES (%s, %s, %s, %s, %s, %s)
        """
        cursor.execute(query, (item, description, quantity, amount, sale_date, fodder_id))
        conn.commit()

    # Fetch all sales records
    cursor.execute("SELECT SaleID, Item, Description, Quantity, Amount, SaleDate, FodderID FROM sales")
    sales_data = cursor.fetchall()

    conn.close()

    return render_template('sales.html', sales_data=sales_data)


@app.route('/procurement', methods=['GET', 'POST'])
def procurement():
    # Connect to the database
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="brayookk7",
        database="livestockmanagement"
    )
    cursor = conn.cursor()

    if request.method == 'POST':
        # Add a new procurement record
        item_name = request.form['item_name']
        description = request.form['description']
        quantity = request.form['quantity']
        unit = request.form['unit']
        purchase_date = request.form['purchase_date']
        section_id = request.form['section_id']
        supplier = request.form['supplier']
        cost = request.form['cost']

        query = """
            INSERT INTO procurementrecord (ItemName, Description, Quantity, Unit, PurchaseDate, SectionID, Supplier, Cost)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """
        cursor.execute(query, (item_name, description, quantity, unit, purchase_date, section_id, supplier, cost))
        conn.commit()

    # Fetch all procurement records
    cursor.execute("""
        SELECT ProcurementID, ItemName, Description, Quantity, Unit, PurchaseDate, SectionID, Supplier, Cost
        FROM procurementrecord
    """)
    procurement_data = cursor.fetchall()

    conn.close()

    return render_template('procurement.html', procurement_data=procurement_data)

@app.route('/routine_operations', methods=['GET', 'POST'])
def routine_operations():
    # Connect to the database
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="brayookk7",
        database="livestockmanagement"
    )
    cursor = conn.cursor()

    if request.method == 'POST':
        # Add a new routine operation
        activity_type = request.form['activity_type']
        animal_id = request.form['animal_id']
        activity_date = request.form['activity_date']

        query = """
            INSERT INTO routinerecords (RecordID, AnimalID, ActivityDate)
            VALUES (%s, %s, %s)
        """
        cursor.execute(query, (activity_type, animal_id, activity_date))
        conn.commit()

    # Fetch all routine operations
    cursor.execute("""
        SELECT RecordID, Activity, AnimalID, ActivityDate
        FROM routinerecords
    """)
    routine_data = cursor.fetchall()

    conn.close()

    return render_template('routine_operations.html', routine_data=routine_data)

@app.route('/reports_analytics')
def reports_analytics():
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="brayookk7",
        database="livestockmanagement"
    )
    cursor = conn.cursor()

    # Fetch table names dynamically
    cursor.execute("SHOW TABLES")
    tables = [table[0] for table in cursor.fetchall()]

    conn.close()

    return render_template('reports_analytics.html', tables=tables)


@app.route('/fetch_table_data', methods=['POST'])
def fetch_table_data():
    table_name = request.form['table_name']

    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="brayookk7",
        database="livestockmanagement"
    )
    cursor = conn.cursor()

    # Fetch column names
    cursor.execute(f"SHOW COLUMNS FROM {table_name}")
    columns = [col[0] for col in cursor.fetchall()]

    # Fetch table data
    cursor.execute(f"SELECT * FROM {table_name}")
    data = cursor.fetchall()

    conn.close()

    return jsonify({'columns': columns, 'data': data})

@app.route('/user_management')
def user_management():
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="brayookk7",
        database="livestockmanagement"
    )
    cursor = conn.cursor()

    # Fetch all users
    cursor.execute("SELECT Username, Role FROM user")
    users = cursor.fetchall()

    conn.close()

    return render_template('user_management.html', users=users)

@app.route('/add_user', methods=['POST'])
def add_user():
    username = request.form['username']
    email = request.form['email']
    password = request.form['password']
    role = request.form['role']

    # Hash the password before storing it
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="brayookk7",
        database="livestockmanagement"
    )
    cursor = conn.cursor()

    try:
        # Insert the new user into the database
        cursor.execute(
            "INSERT INTO user (Username,Email, Password, Role) VALUES (%s,%s, %s, %s)",
            (username, email, hashed_password, role)
        )
        conn.commit()
        flash('User added successfully!', 'success')
    except Exception as e:
        flash(f'Error: {e}', 'danger')
    finally:
        cursor.close()
        conn.close()

    return redirect('/user_management')

@app.route('/delete_user', methods=['POST'])
def delete_user():
    username = request.form['username']

    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="brayookk7",
        database="livestockmanagement"
    )
    cursor = conn.cursor()

    try:
        # Delete the user from the database
        cursor.execute("DELETE FROM user WHERE Username = %s", (username,))
        conn.commit()
        flash('User deleted successfully!', 'success')
    except Exception as e:
        flash(f'Error: {e}', 'danger')
    finally:
        conn.close()

    return redirect('/user_management')

@app.route('/nutrition_feeding_management', methods=['GET', 'POST'])
def nutrition_feeding_management():
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="brayookk7",
        database="livestockmanagement"
    )
    cursor = conn.cursor()

    # Initialize variables
    feeding_programmes = []
    fodder_production_records = []
    feed_conversion_ratios = []

    try:
        # Fetch Feeding Programmes
        cursor.execute("""
            SELECT AnimalID, DescriptionOfProgramme, FeedType, FeedAmount, FeedConversionRatio, GrowthRates, ScheduledTime
            FROM feedingprogrammerecord
        """)
        feeding_programmes = cursor.fetchall()

        # Fetch Fodder Production Records
        cursor.execute("""
            SELECT TypeOfFodder, QuantityProduced, Acreage, PlantingDate, CuttingDate
            FROM fodderproduction
        """)
        fodder_production_records = cursor.fetchall()

        # Calculate Feed Conversion Ratios (if needed for charts or analysis)
        cursor.execute("""
            SELECT FeedType, AVG(FeedConversionRatio) AS AverageConversion
            FROM feedingprogrammerecord
            GROUP BY FeedType
        """)
        feed_conversion_ratios = cursor.fetchall()
    except Exception as e:
        print(f"Error fetching nutrition and feeding data: {e}")
    finally:
        conn.close()

    # Render the Nutrition and Feeding Management template
    return render_template(
        'nutrition_feeding_management.html',
        feeding_programmes=feeding_programmes,
        fodder_production_records=fodder_production_records,
        feed_conversion_ratios=feed_conversion_ratios
    )


@app.route('/milking_records', methods=['GET', 'POST'])
def milking_records():
    # Fetch milking records
    records = milkingrecord.query.order_by(milkingrecord.date.desc()).all()

    # Fetch all animal IDs for the dropdown
    animals = birthidentificationrecord.query.with_entities(birthidentificationrecord.id).all()

    return render_template('milking_records.html', records=records, animals=animals)

@app.route('/add_milk_record', methods=['POST'])
def add_milk_record():
    animal_id = request.form['animal_id']
    date = datetime.strptime(request.form['date'], '%Y-%m-%d')
    morning_milk = float(request.form['morning_milk'])
    evening_milk = float(request.form['evening_milk'])
    total_milk = morning_milk + evening_milk
    notes = request.form['notes']

    # Add new record to the database
    new_record = milkingrecord(
        animal_id=animal_id,
        date=date,
        morning_milk=morning_milk,
        evening_milk=evening_milk,
        total_milk=total_milk,
        notes=notes
    )
    db.session.add(new_record)
    db.session.commit()

    return redirect(url_for('milking_records'))

@app.route('/download_milking_records', methods=['GET'])
def download_milking_records():
    records = milkingrecord.query.all()
    csv_data = "Animal ID,Date,Morning Milk (L),Evening Milk (L),Total Milk (L),Notes\n"
    for record in records:
        csv_data += f"{record.animal_id},{record.date},{record.morning_milk},{record.evening_milk},{record.total_milk},{record.notes}\n"

    response = make_response(csv_data)
    response.headers["Content-Disposition"] = "attachment; filename=milking_records.csv"
    response.headers["Content-Type"] = "text/csv"
    return response

@app.route('/health_management')
def health_management():
    return render_template('health_management.html')

@app.route('/vaccination_records', methods=['GET', 'POST'])
def vaccination_records():
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="brayookk7",
        database="livestockmanagement"
    )
    cursor = conn.cursor()

    search_term = request.form.get('search_term', '')
    vaccination_records = []

    try:
        query = """
            SELECT VaccinationID, AnimalID, VaccinationType, DewormingType, VaccinationDate, Veterinarian, Notes
            FROM healthvaccinationrecord
            WHERE AnimalID LIKE %s OR VaccinationType LIKE %s
        """
        search_value = f"%{search_term}%"
        cursor.execute(query, (search_value, search_value))
        vaccination_records = cursor.fetchall()
    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()

    return render_template('vaccination_records.html', vaccination_records=vaccination_records)

def reset_auto_increment():
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="brayookk7",
        database="livestockmanagement"
    )
    cursor = conn.cursor()

    try:
        # Get the highest existing ID
        cursor.execute("SELECT MAX(VaccinationID) FROM healthvaccinationrecord")
        max_id = cursor.fetchone()[0]

        if max_id:
            # Reset auto-increment to max_id + 1
            cursor.execute(f"ALTER TABLE healthvaccinationrecord AUTO_INCREMENT = {max_id + 1}")
            conn.commit()
    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()


@app.route('/add_vaccination', methods=['POST'])
def add_vaccination():
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="brayookk7",
        database="livestockmanagement"
    )
    cursor = conn.cursor()

    try:
        # Reset auto-increment before inserting a new record
        reset_auto_increment()

        # Get form data
        animal_id = request.form['animal_id']
        vaccination_type = request.form['vaccination_type']
        deworming_type = request.form.get('deworming_type', None)
        vaccination_date = request.form['vaccination_date']
        veterinarian = request.form.get('veterinarian', None)
        notes = request.form.get('notes', None)

        # Insert into the correct table
        query = """
            INSERT INTO healthvaccinationrecord 
            (AnimalID, VaccinationType, DewormingType, VaccinationDate, Veterinarian, Notes)
            VALUES (%s, %s, %s, %s, %s, %s)
        """
        cursor.execute(query, (animal_id, vaccination_type, deworming_type, vaccination_date, veterinarian, notes))
        conn.commit()


    except Exception as e:

        conn.rollback()  # Rollback transaction to prevent gaps

        print(f"Error: {e}")  # Print error for debugging

        return "Failed to insert record: " + str(e), 400
    finally:
        conn.close()

    return redirect(url_for('vaccination_records'))


@app.route('/delete_vaccination/<int:vaccination_id>', methods=['POST'])
def delete_vaccination(vaccination_id):
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="brayookk7",
        database="livestockmanagement"
    )
    cursor = conn.cursor()

    try:
        # Delete the record
        query = "DELETE FROM healthvaccinationrecord WHERE VaccinationID = %s"
        cursor.execute(query, (vaccination_id,))
        conn.commit()

        # Reset auto-increment after deletion
        reset_auto_increment()

    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()

    return redirect(url_for('vaccination_records'))


@app.route('/add_dipping_record', methods=['POST'])
def add_dipping_record():
    conn = get_db_connection()
    cursor = conn.cursor()

    date = request.form['date']
    number_of_animals = request.form['number_of_animals']
    water_added = request.form.get('water_added') or None
    acaricide_type = request.form.get('acaricide_type') or None
    acaricide_amount = request.form.get('acaricide_amount') or None
    lab_test = request.form.get('lab_test') or None

    try:
        query = """
            INSERT INTO dippingrecord (Date, NumberOfAnimals, WaterAdded, AcaricideType, AcaricideAmount, AttachLabTest)
            VALUES (%s, %s, %s, %s, %s, %s)
        """
        cursor.execute(query, (date, number_of_animals, water_added, acaricide_type, acaricide_amount, lab_test))
        conn.commit()
    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()

    return redirect(url_for('dipping_records'))



@app.route('/dipping_records', methods=['GET', 'POST'])
def dipping_records():
    conn = get_db_connection()
    cursor = conn.cursor()

    search_term = request.form.get('search_term', '')

    dipping_records = []
    try:
        query = """
            SELECT Date, NumberOfAnimals, WaterAdded, AcaricideType, AcaricideAmount, AttachLabTest
            FROM dippingrecord
            WHERE Date LIKE %s OR AcaricideType LIKE %s
        """
        search_value = f"%{search_term}%" if search_term else "%"
        cursor.execute(query, (search_value, search_value))
        dipping_records = cursor.fetchall()
    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()

    return render_template('dipping_records.html', dipping_records=dipping_records)


@app.route('/health_response', methods=['GET', 'POST'])
def health_response():
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="brayookk7",
        database="livestockmanagement"
    )
    cursor = conn.cursor(dictionary=True)

    try:
        # Fetch treatment records
        cursor.execute("SELECT TreatmentID, AnimalID, TreatmentDate, Diagnosis, DrugAdministered, Dosage FROM healthtreatmentrecord")
        treatment_records = cursor.fetchall()

        # Fetch logged responses
        cursor.execute("SELECT AnimalId, Response, LoggedDate FROM health_response_record")
        response_log = cursor.fetchall()

    except Exception as e:
        print(f"Error: {e}")
        treatment_records, response_log = [], []

    finally:
        cursor.close()
        conn.close()

    return render_template("health_response.html", treatment_records=treatment_records, response_log=response_log)


@app.route('/add_treatment', methods=['POST'])
def add_treatment():
    animal_id = request.form.get("animal_id")
    treatment_date = request.form.get("treatment_date")
    diagnosis = request.form.get("diagnosis")
    drug_administered = request.form.get("drug_administered")
    dosage = request.form.get("dosage")

    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="brayookk7",
        database="livestockmanagement"
    )
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO healthtreatmentrecord (AnimalID, TreatmentDate, Diagnosis, DrugAdministered, Dosage)
        VALUES (%s, %s, %s, %s, %s)
    """, (animal_id, treatment_date, diagnosis, drug_administered, dosage))

    conn.commit()
    cursor.close()
    conn.close()

    return redirect('/health_response')

@app.route('/log_health_response', methods=['POST'])
def log_health_response():
    treatment_id = request.form.get("treatment_id")
    response = request.form.get("response")

    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="brayookk7",
        database="livestockmanagement"
    )
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO healthresponserecord (AnimalID, Response, LoggedDate)
        SELECT TreatmentID, AnimalID, %s, NOW() FROM healthtreatmentrecord WHERE TreatmentID = %s
    """, (response, treatment_id))

    conn.commit()
    cursor.close()
    conn.close()

    return redirect('/health_response')


@app.route('/weight_records', methods=['GET', 'POST'])
def weight_records():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # Fetch all animals for selection
        cursor.execute("SELECT AnimalID FROM birthidentificationrecord")
        animals = cursor.fetchall()

        # Search for an animal's growth data
        animal_id = request.args.get('animal_id')
        growth_data = []

        if animal_id:
            cursor.execute("""
                SELECT WeightDate, Weight, ChestGirth, ScrotalLength, ScrotalWidth, ScrotalCircumference 
                FROM weightbodymeasurementrecord WHERE AnimalID = %s ORDER BY WeightDate ASC
            """, (animal_id,))
            growth_data = cursor.fetchall()

        # Add a new record
        if request.method == 'POST':
            animal_id = request.form['animal_id']
            reason = request.form['reason']
            weight_date = request.form['weight_date']

            try:
                weight = float(request.form['weight'])
                chest_girth = float(request.form['chest_girth']) if request.form['chest_girth'] else None
                scrotal_length = float(request.form['scrotal_length']) if request.form['scrotal_length'] else None
                scrotal_width = float(request.form['scrotal_width']) if request.form['scrotal_width'] else None
                scrotal_circumference = float(request.form['scrotal_circumference']) if request.form['scrotal_circumference'] else None
            except ValueError:
                flash("Invalid numeric input", "danger")
                return redirect(url_for('weight_records'))

            # Check for duplicate entry
            cursor.execute("""
                SELECT COUNT(*) as count FROM weightbodymeasurementrecord 
                WHERE AnimalID = %s AND WeightDate = %s
            """, (animal_id, weight_date))
            existing_record = cursor.fetchone()

            if existing_record['count'] > 0:
                flash("A record already exists for this date", "warning")
                return redirect(url_for('weight_records'))

            cursor.execute("""
                INSERT INTO weightbodymeasurementrecord (AnimalID, Reason, WeightDate, Weight, ChestGirth, ScrotalLength, ScrotalWidth, ScrotalCircumference)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (animal_id, reason, weight_date, weight, chest_girth, scrotal_length, scrotal_width, scrotal_circumference))

            conn.commit()
            flash("Weight Record Added Successfully", "success")
            return redirect(url_for('weight_records'))

        return render_template("weight_records.html", animals=animals, growth_data=growth_data, animal_id=animal_id)

    finally:
        conn.close()


@app.route('/get_growth_data', methods=['GET'])
def get_growth_data():
    animal_id = request.args.get('animal_id')

    if not animal_id:
        return jsonify({"error": "Animal ID is required"}), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT WeightDate, Weight, ChestGirth, ScrotalLength, ScrotalWidth, ScrotalCircumference 
        FROM weightbodymeasurementrecord 
        WHERE AnimalID = %s 
        ORDER BY WeightDate ASC
    """, (animal_id,))

    growth_data = cursor.fetchall()
    conn.close()

    return jsonify(growth_data)


@app.route("/audit_trail")
def audit_trail():
    logs = get_audit_logs()
    return render_template("admin.html", audit_logs=logs)


@app.route('/feeding_programmes', methods=['GET', 'POST'])
def feeding_programmes():
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="brayookk7",
        database="livestockmanagement"
    )
    cursor = conn.cursor()

    # Handle form submission
    if request.method == 'POST':
        animal_id = request.form['animal_id']
        description = request.form['description']
        feed_type = request.form['feed_type']
        feed_amount = request.form['feed_amount']
        feed_conversion_ratio = request.form.get('feed_conversion_ratio', 'N/A')
        growth_rates = request.form.get('growth_rates', 'N/A')
        scheduled_time = request.form['scheduled_time']
        fodder_id = request.form.get('fodder_id')
        procurement_id = request.form.get('procurement_id')

        query = """INSERT INTO feedingprogrammerecord (AnimalID, DescriptionOfProgramme, FeedType, FeedAmount, 
                        FeedConversionRatio, GrowthRates, ScheduledTime, FodderID, ProcurementID) 
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)"""
        cursor.execute(query, (animal_id, description, feed_type, feed_amount,
                               feed_conversion_ratio, growth_rates, scheduled_time, fodder_id, procurement_id))
        conn.commit()

    # Fetch feed consumption trends (grouped by week)
    cursor.execute("""
            SELECT WEEK(ScheduledTime) AS week, SUM(FeedAmount) AS total_feed 
            FROM feedingprogrammerecord 
            GROUP BY week 
            ORDER BY week ASC
        """)
    feed_trends = cursor.fetchall()

    # Fetch all feeding records
    cursor.execute("SELECT * FROM feedingprogrammerecord ORDER BY ScheduledTime DESC")
    feeding_records = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template("feeding_programmes.html", feed_trends=feed_trends, feeding_records=feeding_records)


@app.route('/get_feed_trends')
def get_feed_trends():
    # Connect to database
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="brayookk7",
        database="livestockmanagement"
    )
    cursor = conn.cursor()

    # Get feeding trend data
    cursor.execute("""
            SELECT WEEK(ScheduledTime) AS week, SUM(FeedAmount) AS total_feed 
            FROM feedingprogrammerecord 
            GROUP BY week 
            ORDER BY week ASC
        """)
    feed_trends = cursor.fetchall()

    cursor.close()
    conn.close()

    # Convert data into JSON format
    labels = [f"Week {row[0]}" for row in feed_trends]
    data = [row[1] for row in feed_trends]

    return jsonify({"labels": labels, "data": data})

@app.route('/fodder_production', methods=['GET', 'POST'])
def fodder_production():
    # Connect to the database
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="brayookk7",
        database="livestockmanagement"
    )
    cursor = conn.cursor()

    if request.method == 'POST':
        # Add a new fodder production record
        data = (
            request.form['fodder_type'],
            request.form['quantity'],
            request.form['acreage'],
            request.form['planting_date'],
            request.form['cutting_date']
        )
        query = """
            INSERT INTO fodderproduction (TypeOfFodder, QuantityProduced, Acreage, PlantingDate, CuttingDate)
            VALUES (%s, %s, %s, %s, %s)
        """
        cursor.execute(query, data)
        conn.commit()

    # Fetch all fodder production records
    cursor.execute("SELECT TypeOfFodder, QuantityProduced, Acreage, PlantingDate, CuttingDate FROM fodderproduction")
    fodder_data = cursor.fetchall()

    conn.close()

    return render_template('fodder_production.html', fodder_data=fodder_data)


# Route for the animal report page
@app.route('/animal_report', methods=['GET', 'POST'])
def animal_report():
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="brayookk7",
        database="livestockmanagement"
    )
    cursor = conn.cursor()

    # Fetch unique species and breeds for dropdowns
    cursor.execute("SELECT DISTINCT Species FROM birthidentificationrecord")
    species_list = [row[0] for row in cursor.fetchall()]

    cursor.execute("SELECT DISTINCT Breed FROM birthidentificationrecord")
    breed_list = [row[0] for row in cursor.fetchall()]

    # Default data to None
    animal_data = []

    if request.method == 'POST':
        # Get selected filters
        species = request.form.get('species')
        breed = request.form.get('breed')
        animal_id = request.form.get('animal_id')  # Get animal ID from the search bar

        # Build the query dynamically based on selected filters
        query = "SELECT AninamID, Species, Breed, Sex, DamNumber, SireNumber, DateOfBirth, DateAcquired, BirthWeight, Color FROM birthidentificationrecord WHERE 1=1"
        params = []

        if species:
            query += " AND species = %s"
            params.append(species)

        if breed:
            query += " AND breed = %s"
            params.append(breed)

        if animal_id:
            query += " AND id = %s"
            params.append(animal_id)

        cursor.execute(query, tuple(params))
        animal_data = cursor.fetchall()

    conn.close()

    return render_template(
        'animal_report.html',
        species_list=species_list,
        breed_list=breed_list,
        animal_data=animal_data
    )


@app.route('/inventory', methods=['GET', 'POST'])
def inventory():
    # Mocked inventory data; replace with database query
    inventory = [
        {'item_name': 'Animal Feed', 'category': 'Feed', 'stock_quantity': 20, 'unit_price': 50, 'last_updated': '2025-01-10', 'alert_threshold': 10},
        {'item_name': 'Vaccines', 'category': 'Veterinary', 'stock_quantity': 5, 'unit_price': 100, 'last_updated': '2025-01-08', 'alert_threshold': 10},
    ]

    search = request.args.get('search', '')
    filter_option = request.args.get('filter', 'all')

    # Apply search and filter logic
    if search:
        inventory = [item for item in inventory if search.lower() in item['item_name'].lower() or search.lower() in item['category'].lower()]

    if filter_option == 'low_stock':
        inventory = [item for item in inventory if item['stock_quantity'] < item['alert_threshold']]
    elif filter_option == 'out_of_stock':
        inventory = [item for item in inventory if item['stock_quantity'] == 0]

    return render_template('inventory.html', inventory=inventory)


@app.route('/add_health_record', methods=['POST'])
@roles_required('scientist', 'admin')
def add_health_record():
    # Extract form data
    calf_id = request.form['calf_id']
    health_record = request.form['health_record']
    # Save to the database

    return redirect(url_for('calvings'))

@app.route('/view_schedules', methods=['GET'])
@roles_required('scientist', 'admin')
def view_schedules():
    # Extract form data
    calf_id_schedule = request.args['calf_id_schedule']
    # Fetch from the database

    # For now, let's return a simple page
    schedules = [
        {'task': 'Feeding', 'time': '08:00 AM'},
        {'task': 'Health Check', 'time': '12:00 PM'}
    ]
    return render_template('schedules.html', schedules=schedules, calf_id=calf_id_schedule)


@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    user_id = session['user_id']

    if request.method == 'POST':
        if 'update_profile' in request.form:
            name = request.form['name']
            email = request.form['email']
            password = request.form['password']

            if password:
                hashed_password = generate_password_hash(password)
                cursor.execute("UPDATE user SET Username=%s, Email=%s, Password=%s WHERE UserID=%s",
                               (name, email, hashed_password, user_id))
            else:
                cursor.execute("UPDATE user SET Username=%s, Email=%s WHERE UserID=%s", (name, email, user_id))
            conn.commit()
            flash("Profile updated successfully!", "success")

    cursor.execute("SELECT UserID, Username, Email FROM user WHERE UserID=%s", (user_id,))
    user = cursor.fetchone()

    cursor.close()
    conn.close()

    return render_template('settings.html', user=user)

def get_notification_settings(user_id):
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="brayookk7",
        database="livestockmanagement"
    )
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT notifications_enabled FROM notifications_settings WHERE user_id = %s", (user_id,))
    result = cursor.fetchone()

    cursor.close()
    conn.close()

    if result:
        return result["notifications_enabled"]
    else:
        return True  # Default to True if no record exists

@app.route('/update_notification_settings', methods=['POST'])
def update_notification_settings():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 403

    user_id = session['user_id']
    notifications_enabled = request.json.get('notifications_enabled', True)

    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="brayookk7",
        database="livestockmanagement"
    )
    cursor = conn.cursor()

    # Check if user already has a notification setting
    cursor.execute("SELECT * FROM notifications_settings WHERE user_id = %s", (user_id,))
    existing = cursor.fetchone()

    if existing:
        cursor.execute("UPDATE notifications_settings SET notifications_enabled = %s WHERE user_id = %s",
                       (notifications_enabled, user_id))
    else:
        cursor.execute("INSERT INTO notifications_settings (user_id, notifications_enabled) VALUES (%s, %s)",
                       (user_id, notifications_enabled))

    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({"message": "Notification settings updated successfully"})
@app.route('/get_notifications', methods=['GET'])
def get_notifications():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 403

    user_id = session['user_id']
    status = get_notification_settings(user_id)

    return jsonify({"notifications_enabled": status})


if __name__ == '__main__':
    Timer(1, open_browser).start() #open the browser after 1 second
    app.run(debug=True)
