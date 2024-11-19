from flask import Flask, app, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from datetime import datetime
from flask import render_template, request, redirect, url_for
import mysql.connector
from sqlalchemy import or_
import webbrowser

from flask_mail import Mail, Message
from functools import wraps

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:brayookk7@localhost/livestock'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'supersecretkey'

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

db = SQLAlchemy(app)
migrate = Migrate(app, db)

def roles_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = User.query.filter_by(id=session.get('user_id')).first()  # Assuming you store user_id in session
            if not user or (user.role not in roles and user.role != 'admin'):
                flash('You do not have permission to access this page', 'error')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# User and Cattle Models#z
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(50), nullable=False, default="user")

class animal(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    species = db.Column(db.String(80), nullable=False)
    breed = db.Column(db.String(80), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    weight = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(50), nullable=False)

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


# Routes

@app.route('/')
def home():
    #cattle = animal.query.all()
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username, password=password).first()

        if user and user.password == password:
            session['user_id'] = user.id
            session['user_role'] = user.role
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error="Invalid username or password")
    return render_template('login.html')


@app.route('/admin')
@roles_required('admin')  # Only admins can access this page
def admin_dashboard():
    return render_template('admin.html')

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
        user.role = request.form['role']
        db.session.commit()
        flash("User information updated successfully", "success")
        return redirect(url_for('view_users'))
    return render_template('edit_user.html', user=user)

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@roles_required('admin')  # Only admins can access this
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash("User deleted successfully", "success")
    return redirect(url_for('view_users'))


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
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        role = request.form.get('role', 'user')

        # Check if the username or email already exists
        existing_user = User.query.filter(
            (User.username == username) | (User.email == email)
        ).first()

        if existing_user:
            return render_template('register.html', error="Username or Email already exists")

        # Create a new user
        new_user = User(username=username, email=email,  password=password, role=role)
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('login'))  # Redirect to login after successful registration

    return render_template('register.html')


@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')


@app.route('/register_cow', methods=['GET', 'POST'])
@roles_required('scientist', 'admin', 'user')
def register_cow():
    if request.method == 'POST':

        pass

        species = request.form['name']
        breed = request.form['breed']
        age = request.form['age']
        weight = request.form['weight']
        status = request.form['status']

        print(f"Name: {species}, Breed: {breed}, Age: {age}, Weight: {weight}, Status: {status}")

        new_cow = animal(name=species, breed=breed, age=int(age), weight=float(weight), status=status)

        db.session.add(new_cow)
        db.session.commit()

        return redirect(url_for('dashboard'))

    return render_template('register_cow.html')

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

@app.route('/cows')
@roles_required('scientist', 'admin', 'user')
def cows():
    cows = animal.query.all()
    breed_labels = ["Breed A", "Breed B"]
    breed_data = [10, 5]
    breeds = {}
    for cow in cows:
        if cow.breed in breeds:
            breeds[cow.breed] += 1
        else:
            breeds[cow.breed] = 1

    breed_labels = list(breeds.keys())
    breed_data = list(breeds.values())

    return render_template('cows.html', cows=cows, breed_labels=breed_labels, breed_data=breed_data, total_cows=len(cows))

@app.route('/total_cows')
@roles_required('scientist', 'admin')
def total_cows():
    # Replace with actual logic
    cows = animal.query.all()
    return render_template('total_cows.html', cows=cows)

@app.route('/cow_types')
@roles_required('scientist', 'admin')
def cow_types():
    # Replace with actual logic
    cow_types = db.session.query(animal.breed, db.func.count(animal.breed)).group_by(animal.breed).all()
    return render_template('cow_types.html', cow_types=cow_types)

@app.route('/search_cows', methods=['POST'])
@roles_required('scientist', 'admin')
def search_cows():
    search_term = request.form.get('search_term')
    # Replace with actual search logic
    cows = animal.query.filter(or_(
        animal.name.ilike(f"%{search_term}%"),
        animal.breed.ilike(f"%{search_term}%")
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

@app.route('/weaners')
def weaners():
    # Retrieve weaners data from the database
    weaners = Calf.query.all() # Replace with actual data retrieval
    return render_template('weaners.html', weaners=weaners)

@app.route('/milk_records')
@roles_required('milk_person', 'admin')
def milk_records():
    # Retrieve milk records data from the database
    milk_records = []  # Replace with actual data retrieval
    return render_template('milk_records.html', milk_records=milk_records)

@app.route('/add_milk_record', methods=['POST'])
@roles_required('milk_person', 'admin')  # Only milk persons can add milk records
def add_milk_record():
    # Logic to add a milk record
    return redirect(url_for('milk_records'))



# Route for the animal report page
@app.route('/animal_report', methods=['GET', 'POST'])
def animal_report():
    # Connect to the database
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="brayookk7",
        database="livestock"
    )
    cursor = conn.cursor()

    # Fetch all animals for the dropdown
    cursor.execute("SELECT id, species FROM animal")
    animals = cursor.fetchall()

    animal_data = None #{}
    reports = []

    if request.method == 'POST':
        # Fetch the selected animal ID
        species = request.form.get('species')
        breed = request.form.get('breed')
        herd = request.form.get('herd')
        animal_id = request.form.get('animal_id')

        # Build query dynamically based on selected filters
        query = "SELECT id, species, breed, age, weight, status, dam_number, sire_number, date_of_birth, date_acquired, color, sex FROM animal WHERE 1=1"
        params = []

        if species:
            query += " AND species = %s"
            params.append(species)

        if breed:
            query += " AND breed = %s"
            params.append(breed)

        if herd:
            query += " AND herd = %s"
            params.append(herd)

        if animal_id:
            query += " AND id = %s"
            params.append(animal_id)

        # Fetch animal data based on filters
        cursor.execute(query, tuple(params))
        animal_data = cursor.fetchone()

        # If an animal is selected, fetch related report data
        if animal_id:
            cursor.execute(
                "SELECT breed, age, sex FROM report WHERE id = %s",
                (animal_id,)
            )
            reports = cursor.fetchall()

    conn.close()

    # Render template with data
    return render_template('animal_report.html', animals=animals, animal_data=animal_data, reports=reports)




@app.route('/inventory')
def inventory():
    # Retrieve inventory data from the database
    inventory = []  # Replace with actual data retrieval
    return render_template('inventory.html', inventory=inventory)

@app.route('/register_calf', methods=['POST'])
@roles_required('scientist', 'admin')
def register_calf():
    # Extract form data

    calf_name = request.form['calf_name']
    calf_birth_date = request.form['calf_birth_date']
    calf_breed = request.form['calf_breed']
    calf_weight = request.form['calf_weight']
    dam_name = ['dam_name']
    sire_name = ['sire_name']

    calf_birth_date = datetime.strptime(calf_birth_date, '%Y-%m-%d')

    new_calf = Calf(calf_name=calf_name, calf_birth_date=calf_birth_date, calf_breed=calf_breed, calf_weight=calf_weight, dam_name=dam_name, sire_name=sire_name)
    # Save to the database
    db.session.add(new_calf)
    db.session.commit()

    return redirect(url_for('calvings'))

@app.route('/view_calves', methods=['GET'])
@roles_required('scientist', 'admin')
def view_calves():
    # Query all calves from the database
    calves = Calf.query.all()

    # Pass the list of calves to the template
    return render_template('view_calves.html', calves=calves)


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




if __name__ == '__main__':
    app.run(debug=True)
