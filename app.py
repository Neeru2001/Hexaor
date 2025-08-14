from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
import mysql.connector
from mysql.connector import pooling
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import re, datetime
from werkzeug.exceptions import HTTPException
import os, sys
from dotenv import load_dotenv

# Load environment variables from .env file for local development
load_dotenv()

app = Flask(__name__)
# A secret key is required for session management. Load from environment variable.
app.secret_key = os.environ.get('FLASK_SECRET_KEY')

# --- Database Connection Pool ---
# A connection pool is more efficient for web apps than creating new connections for every request.
try:
    db_pool = mysql.connector.pooling.MySQLConnectionPool(
        pool_name="web_app_pool",
        pool_size=5,
        host=os.environ.get('DB_HOST'),
        user=os.environ.get('DB_USER'),
        password=os.environ.get('DB_PASSWORD'),
        database=os.environ.get('DB_NAME'),
        port=os.environ.get('DB_PORT', 3306),
        # PlanetScale requires a secure SSL connection. This enables it.
        ssl_verify_cert=True
    )
    print("Database connection pool created successfully.")
except mysql.connector.Error as err:
    print(f"Error creating connection pool: {err}")
    print("CRITICAL: Could not connect to the database. Please check your .env configuration and ensure the database server is running.")
    sys.exit(1) # Exit if the database connection fails on startup.

# --- Central Logging Function ---
def log_event(level, message, endpoint=None, method=None, user_id=None, ip_address=None):
    """A central function to log events to the database."""
    try:
        conn = db_pool.get_connection()
        cursor = conn.cursor()
        
        # If details aren't provided, try to get them from the current request context
        if request:
            endpoint = endpoint or request.endpoint
            method = method or request.method
            ip_address = ip_address or request.remote_addr
        if user_id is None and 'user_id' in session:
            user_id = session.get('user_id')

        cursor.execute(
            """INSERT INTO logs (level, message, endpoint, method, user_id, ip_address)
               VALUES (%s, %s, %s, %s, %s, %s)""",
            (level, message, endpoint, method, user_id, ip_address)
        )
        conn.commit()
    except Exception as e:
        # If logging fails, we print the error but don't crash the app
        print(f"--- CRITICAL: FAILED TO LOG EVENT: {e} ---")
    finally:
        if 'conn' in locals() and conn.is_connected():
            cursor.close()
            conn.close()

# --- Automatic Request and Error Logging ---

@app.after_request
def log_request(response):
    """Log every successful request after it's handled."""
    # Avoid logging requests for static files to keep the log clean
    if request.endpoint and 'static' not in request.endpoint:
        # We only log successful requests here (2xx and 3xx status codes)
        if 200 <= response.status_code < 400:
            log_event('INFO', f"Request to '{request.path}' status {response.status_code}")
    return response

@app.errorhandler(Exception)
def handle_exception(e):
    """Log all unhandled exceptions."""
    # Pass through standard HTTP errors
    if isinstance(e, HTTPException):
        return e
    log_event('ERROR', str(e))
    return "An internal server error occurred.", 500

# --- Admin-only Decorator ---
def admin_required(f):
    """
    A decorator to ensure a route is only accessible by admin users.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin'):
            # Log the unauthorized access attempt
            log_event('WARNING', f"Unauthorized access attempt to admin route: {request.path}")
            return redirect(url_for('welcome')) # Redirect non-admins to the home page
        return f(*args, **kwargs)
    return decorated_function

# --- Authentication Routes ---

@app.route('/')
def index():
    # If a user is already logged in, send them to the welcome page
    if 'user_id' in session:
        return redirect(url_for('welcome'))
    # Otherwise, show the login page
    return render_template('login.html')

@app.route('/show_register')
def show_register():
    return render_template('register.html')

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')

    if not name or not email or not password:
        return jsonify({'success': False, 'message': 'All fields are required.'})

    # Securely hash the password before storing it
    hashed_password = generate_password_hash(password)

    try:
        conn = db_pool.get_connection()
        cursor = conn.cursor()

        # Check if the email is already in use
        cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
        if cursor.fetchone():
            return jsonify({'success': False, 'message': 'Email already registered.'})

        # Insert the new user into the database
        cursor.execute(
            "INSERT INTO users (name, email, password) VALUES (%s, %s, %s)",
            (name, email, hashed_password)
        )
        conn.commit()

        log_event('INFO', f"New user registered: '{email}'.")
        return jsonify({
            'success': True,
            'message': 'Registration successful! Redirecting to login...',
            'redirect_url': url_for('index')
        })
    except mysql.connector.Error as err:
        print(f"Database Error on registration: {err}")
        return jsonify({'success': False, 'message': 'A database error occurred.'})
    finally:
        # Always close the cursor and return the connection to the pool
        if 'conn' in locals() and conn.is_connected():
            cursor.close()
            conn.close()

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'success': False, 'message': 'Email and password are required.'})

    try:
        conn = db_pool.get_connection()
        # Use a dictionary cursor to access columns by name (e.g., user['password'])
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        # Check if user exists and the password hash matches
        if user and check_password_hash(user['password'], password):
            # Store user info in the session to keep them logged in
            session['user_id'] = user['id']
            session['user_name'] = user['name']
            session['is_admin'] = user['is_admin']
            
            log_event('INFO', f"User '{user['email']}' logged in successfully.", user_id=user['id'])
            return jsonify({
                'success': True,
                'redirect_url': url_for('welcome')
            })
        else:
            log_event('WARNING', f"Failed login attempt for email '{email}'.")
            return jsonify({'success': False, 'message': 'Invalid email or password.'})
    except mysql.connector.Error as err:
        print(f"Database Error on login: {err}")
        return jsonify({'success': False, 'message': 'A server error occurred.'})
    finally:
        if 'conn' in locals() and conn.is_connected():
            cursor.close()
            conn.close()

@app.route('/logout')
def logout():
    user_id = session.get('user_id')
    # Clear the session to log the user out
    log_event('INFO', "User logged out.", user_id=user_id)
    session.clear()
    return redirect(url_for('index'))

# --- Content Routes (Placeholders) ---

@app.route('/welcome')
def welcome():
    if 'user_id' not in session:
        return redirect(url_for('index'))

    next_appointment = None
    try:
        conn = db_pool.get_connection()
        cursor = conn.cursor(dictionary=True)
        # Find the user's soonest upcoming appointment that is not completed or cancelled
        cursor.execute(
            """SELECT * FROM appointments 
               WHERE user_id = %s AND status IN ('Pending', 'Confirmed') AND preferred_date >= CURDATE()
               ORDER BY preferred_date ASC, preferred_time ASC LIMIT 1""",
            (session['user_id'],)
        )
        next_appointment = cursor.fetchone()
    except mysql.connector.Error as err:
        print(f"Database error on welcome page: {err}")
        # Don't crash the page if the query fails, just proceed without appointment data
    finally:
        if 'conn' in locals() and conn.is_connected():
            cursor.close()
            conn.close()

    return render_template('welcome.html', active_page='home', next_appointment=next_appointment)

@app.route('/contact')
def contact():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    
    user_details = None
    try:
        conn = db_pool.get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT name, email, phone_number FROM users WHERE id = %s", (session['user_id'],))
        user_details = cursor.fetchone()
    except mysql.connector.Error as err:
        print(f"Database error on contact page load: {err}")
    finally:
        if 'conn' in locals() and conn.is_connected():
            cursor.close()
            conn.close()

    return render_template('contact.html', active_page='contact', user=user_details)

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    
    user_details = None
    appointments = []
    try:
        conn = db_pool.get_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Get user details
        cursor.execute("SELECT id, name, email, phone_number, created_at FROM users WHERE id = %s", (session['user_id'],))
        user_details = cursor.fetchone()
        
        # Get user's appointment history
        cursor.execute("SELECT * FROM appointments WHERE user_id = %s ORDER BY created_at DESC", (session['user_id'],))
        appointments = cursor.fetchall()
        
    except mysql.connector.Error as err:
        print(f"Database error on profile page: {err}")
    finally:
        if 'conn' in locals() and conn.is_connected():
            cursor.close()
            conn.close()
            
    return render_template('profile.html', active_page='profile', user=user_details, appointments=appointments)

@app.route('/update_profile', methods=['POST'])
def update_profile():
    if 'user_id' not in session:
        return redirect(url_for('index'))

    user_id = session['user_id']
    name = request.form.get('name', '').strip()
    email = request.form.get('email', '').strip()
    phone_number = request.form.get('phone_number', '').strip()

    errors = False
    if not (2 <= len(name) <= 100):
        flash("Name must be between 2 and 100 characters.", "error")
        errors = True
    
    if not re.match(r'[^@]+@[^@]+\.[^@]+', email):
        flash("Please enter a valid email address.", "error")
        errors = True

    if phone_number: # Phone number is optional
        phone_pattern = re.compile(r'^\(?([0-9]{3})\)?[-. ]?([0-9]{3})[-. ]?([0-9]{4})$')
        if not phone_pattern.match(phone_number):
            flash("Please enter a valid 10-digit phone number or leave it blank.", "error")
            errors = True
    
    if errors:
        return redirect(url_for('profile'))

    try:
        conn = db_pool.get_connection()
        cursor = conn.cursor()
        # Check if email is already taken by another user
        cursor.execute("SELECT id FROM users WHERE email = %s AND id != %s", (email, user_id))
        if cursor.fetchone():
            flash("That email address is already in use by another account.", "error")
            return redirect(url_for('profile'))

        cursor.execute(
            "UPDATE users SET name = %s, email = %s, phone_number = %s WHERE id = %s",
            (name, email, phone_number, user_id)
        )
        conn.commit()
        session['user_name'] = name # Update session with new name
        flash("Profile updated successfully!", "success")
        log_event('INFO', f"User ID {user_id} updated their profile.")
    except mysql.connector.Error as err:
        flash("A database error occurred. Please try again.", "error")
        log_event('ERROR', f"Database error updating profile for user ID {user_id}: {err}")
    finally:
        if 'conn' in locals() and conn.is_connected():
            cursor.close()
            conn.close()

    return redirect(url_for('profile'))

@app.route('/change_password', methods=['POST'])
def change_password():
    if 'user_id' not in session:
        return redirect(url_for('index'))

    user_id = session['user_id']
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')

    if not all([current_password, new_password, confirm_password]):
        flash("All password fields are required.", "error")
        return redirect(url_for('profile'))

    if new_password != confirm_password:
        flash("New passwords do not match.", "error")
        return redirect(url_for('profile'))
    
    if len(new_password) < 8:
        flash("New password must be at least 8 characters long.", "error")
        return redirect(url_for('profile'))

    try:
        conn = db_pool.get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT password FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()

        if not user or not check_password_hash(user['password'], current_password):
            flash("Incorrect current password.", "error")
            return redirect(url_for('profile'))
        
        hashed_password = generate_password_hash(new_password)
        cursor.execute("UPDATE users SET password = %s WHERE id = %s", (hashed_password, user_id))
        conn.commit()

        flash("Password changed successfully!", "success")
        log_event('INFO', f"User ID {user_id} changed their password.")

    except mysql.connector.Error as err:
        flash("A database error occurred. Please try again.", "error")
        log_event('ERROR', f"Database error changing password for user ID {user_id}: {err}")
    finally:
        if 'conn' in locals() and conn.is_connected():
            cursor.close()
            conn.close()

    return redirect(url_for('profile'))

# --- Placeholder routes for footer links ---
@app.route('/newsletter')
@app.route('/newsletter', methods=['GET', 'POST'])
def newsletter():
    if 'user_id' not in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        user_id = session.get('user_id')

        if not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            flash("Please enter a valid email address.", "error")
            return redirect(url_for('newsletter'))

        try:
            conn = db_pool.get_connection()
            cursor = conn.cursor()
            # Check for duplicates
            cursor.execute("SELECT id FROM subscribers WHERE email = %s", (email,))
            if cursor.fetchone():
                flash("This email is already subscribed.", "info")
            else:
                cursor.execute(
                    "INSERT INTO subscribers (email, user_id) VALUES (%s, %s)",
                    (email, user_id)
                )
                conn.commit()
                flash("Thank you for subscribing!", "success")
                log_event('INFO', f"New newsletter subscription: {email}")
        except mysql.connector.Error as err:
            flash("A database error occurred. Please try again.", "error")
            log_event('ERROR', f"Database error on newsletter subscription: {err}")
        finally:
            if 'conn' in locals() and conn.is_connected():
                cursor.close()
                conn.close()
        
        return redirect(url_for('newsletter'))

    # For GET request, fetch user's email to pre-fill
    user_email = ''
    try:
        conn = db_pool.get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT email FROM users WHERE id = %s", (session['user_id'],))
        user = cursor.fetchone()
        if user:
            user_email = user['email']
    except mysql.connector.Error as err:
        print(f"Error fetching user email for newsletter: {err}")
    finally:
        if 'conn' in locals() and conn.is_connected():
            cursor.close()
            conn.close()

    return render_template('newsletter.html', active_page='newsletter', user_email=user_email)

@app.route('/career')
def career():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    return render_template('career.html', active_page='career')

@app.route('/services')
def services():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    return render_template('services.html', active_page='services')

@app.route('/faq')
def faq():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    return render_template('faq.html', active_page='faq')

@app.route('/testimonials')
def testimonials():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    return render_template('testimonials.html', active_page='testimonials')

@app.route('/book-appointment', methods=['GET', 'POST'])
def book_appointment():
    if 'user_id' not in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        form_data = request.form
        user_id = session['user_id']
        vehicle_make = form_data.get('vehicle_make', '').strip()
        vehicle_model = form_data.get('vehicle_model', '').strip()
        vehicle_year = form_data.get('vehicle_year')
        service_required = form_data.get('service_required')
        preferred_date = form_data.get('preferred_date')
        preferred_time = form_data.get('preferred_time')
        phone_number = form_data.get('phone_number', '').strip()
        additional_notes = form_data.get('additional_notes', '').strip()

        errors = {}
        # --- Comprehensive Server-Side Validation ---
        if not (2 <= len(vehicle_make) <= 50):
            errors['vehicle_make'] = "Vehicle make must be between 2 and 50 characters."
        if not (1 <= len(vehicle_model) <= 50):
            errors['vehicle_model'] = "Vehicle model must be between 1 and 50 characters."

        try:
            year = int(vehicle_year)
            current_year = datetime.date.today().year
            if not (1950 <= year <= current_year + 1):
                errors['vehicle_year'] = f"Please enter a valid vehicle year between 1950 and {current_year + 1}."
        except (ValueError, TypeError):
            errors['vehicle_year'] = "Please enter a valid numeric vehicle year."

        try:
            if not preferred_date:
                raise ValueError("Date is required.")
            selected_date = datetime.datetime.strptime(preferred_date, '%Y-%m-%d').date()
            if selected_date < datetime.date.today():
                errors['preferred_date'] = "You cannot book an appointment in the past."
        except (ValueError, TypeError):
            errors['preferred_date'] = "Please enter a valid date."

        phone_pattern = re.compile(r'^\(?([0-9]{3})\)?[-. ]?([0-9]{3})[-. ]?([0-9]{4})$')
        if not phone_pattern.match(phone_number):
            errors['phone_number'] = "Please enter a valid 10-digit phone number."
        
        if not service_required:
            errors['service_required'] = "Please select a service."
        
        if not preferred_time:
            errors['preferred_time'] = "Please select a preferred time."

        if errors:
            return render_template(
                'book_appointment.html',
                active_page='book_appointment',
                errors=errors,
                form_data=form_data
            )

        # If validation passes, proceed to database insertion
        try:
            conn = db_pool.get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """INSERT INTO appointments (user_id, vehicle_make, vehicle_model, vehicle_year, service_required, preferred_date, preferred_time, additional_notes, phone_number)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                (user_id, vehicle_make, vehicle_model, vehicle_year, service_required, preferred_date, preferred_time, additional_notes, phone_number)
            )
            conn.commit()
            log_event('INFO', f"New appointment booked by user ID {user_id}.")
            return redirect(url_for('booking_success'))
        except mysql.connector.Error as err:
            log_event('ERROR', f"Database error on appointment booking: {err}")
            return "An error occurred while booking your appointment. Please try again later.", 500
        finally:
            if 'conn' in locals() and conn.is_connected():
                cursor.close()
                conn.close()

    # For GET request, pass empty dictionaries to prevent template errors
    return render_template('book_appointment.html', active_page='book_appointment', errors={}, form_data={})

@app.route('/booking-success')
def booking_success():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    return render_template('booking_success.html')

# --- Admin Routes ---

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    stats = {}
    try:
        conn = db_pool.get_connection()
        cursor = conn.cursor(dictionary=True)

        # Stat 1: New users this week
        cursor.execute("SELECT COUNT(id) as count FROM users WHERE created_at >= CURDATE() - INTERVAL 7 DAY")
        stats['new_users_week'] = cursor.fetchone()['count']

        # Stat 2: Total contact messages
        cursor.execute("SELECT COUNT(id) as count FROM contacts")
        stats['total_contacts'] = cursor.fetchone()['count']

        # Stat 3: Total log entries
        cursor.execute("SELECT COUNT(id) as count FROM logs")
        stats['total_logs'] = cursor.fetchone()['count']

        # Stat 4: Error logs today
        cursor.execute("SELECT COUNT(id) as count FROM logs WHERE level = 'ERROR' AND timestamp >= CURDATE()")
        stats['errors_today'] = cursor.fetchone()['count']

    except mysql.connector.Error as err:
        print(f"Database error on admin dashboard: {err}")
        # Set default stats on error
        stats = {'new_users_week': 'N/A', 'total_contacts': 'N/A', 'total_logs': 'N/A', 'errors_today': 'N/A'}
    finally:
        if 'conn' in locals() and conn.is_connected():
            cursor.close()
            conn.close()

    return render_template('admin/dashboard.html', stats=stats)

@app.route('/admin/logs')
@admin_required
def admin_logs():
    page = request.args.get('page', 1, type=int)
    per_page = 20
    offset = (page - 1) * per_page

    logs = []
    total_logs = 0
    try:
        conn = db_pool.get_connection()
        cursor = conn.cursor(dictionary=True)

        # Get total number of logs for pagination
        cursor.execute("SELECT COUNT(id) as count FROM logs")
        total_logs = cursor.fetchone()['count']

        # Fetch logs for the current page, joining with users to get email
        query = """
            SELECT l.*, u.email as user_email FROM logs l
            LEFT JOIN users u ON l.user_id = u.id
            ORDER BY l.timestamp DESC
            LIMIT %s OFFSET %s
        """
        cursor.execute(query, (per_page, offset))
        logs = cursor.fetchall()

    except mysql.connector.Error as err:
        print(f"Database error on admin logs page: {err}")
    finally:
        if 'conn' in locals() and conn.is_connected():
            cursor.close()
            conn.close()

    return render_template('admin/logs.html', logs=logs, page=page, per_page=per_page, total_logs=total_logs)

@app.route('/admin/users')
@admin_required
def admin_users():
    users = []
    try:
        conn = db_pool.get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id, name, email, is_admin, created_at FROM users ORDER BY id ASC")
        users = cursor.fetchall()
    except mysql.connector.Error as err:
        print(f"Database error on admin users page: {err}")
    finally:
        if 'conn' in locals() and conn.is_connected():
            cursor.close()
            conn.close()
    return render_template('admin/users.html', users=users)

@app.route('/admin/users/edit/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def admin_edit_user(user_id):
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        # A more pythonic way to check for a checkbox's existence
        is_admin = 'is_admin' in request.form

        try:
            conn = db_pool.get_connection()
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE users SET name = %s, email = %s, is_admin = %s WHERE id = %s",
                (name, email, is_admin, user_id)
            )
            conn.commit()
            log_event('INFO', f"Admin updated user ID {user_id}.")
        except mysql.connector.Error as err:
            print(f"Database error updating user {user_id}: {err}")
        finally:
            if 'conn' in locals() and conn.is_connected():
                cursor.close()
                conn.close()
        return redirect(url_for('admin_users'))

    # For GET request
    user = None
    try:
        conn = db_pool.get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id, name, email, is_admin FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
    except mysql.connector.Error as err:
        print(f"Database error fetching user {user_id} for edit: {err}")
    finally:
        if 'conn' in locals() and conn.is_connected():
            cursor.close()
            conn.close()
    
    if not user:
        return "User not found", 404
        
    return render_template('admin/edit_user.html', user=user)

@app.route('/admin/users/view/<int:user_id>')
@admin_required
def admin_view_user(user_id):
    user = None
    appointments = []
    try:
        conn = db_pool.get_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Get user details
        cursor.execute("SELECT id, name, email, phone_number, is_admin, created_at FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        
        if user:
            # Get user's appointment history
            cursor.execute("SELECT * FROM appointments WHERE user_id = %s ORDER BY created_at DESC", (user_id,))
            appointments = cursor.fetchall()
            
    except mysql.connector.Error as err:
        print(f"Database error viewing user {user_id}: {err}")
    finally:
        if 'conn' in locals() and conn.is_connected():
            cursor.close()
            conn.close()
            
    if not user:
        return "User not found", 404
        
    return render_template('admin/view_user.html', user=user, appointments=appointments)

@app.route('/admin/contacts')
@admin_required
def admin_contacts():
    contacts = []
    try:
        conn = db_pool.get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id, name, email, phone_number, message, submitted_at FROM contacts ORDER BY submitted_at DESC")
        contacts = cursor.fetchall()
    except mysql.connector.Error as err:
        print(f"Database error on admin contacts page: {err}")
    finally:
        if 'conn' in locals() and conn.is_connected():
            cursor.close()
            conn.close()
    return render_template('admin/contacts.html', contacts=contacts)

@app.route('/admin/appointments')
@admin_required
def admin_appointments():
    appointments = []
    try:
        conn = db_pool.get_connection()
        cursor = conn.cursor(dictionary=True)
        # Join with the users table to get customer details
        query = """
            SELECT a.*, u.name as user_name, u.email as user_email
            FROM appointments a
            JOIN users u ON a.user_id = u.id
            ORDER BY a.created_at DESC
        """
        cursor.execute(query)
        appointments = cursor.fetchall()
    except mysql.connector.Error as err:
        print(f"Database error on admin appointments page: {err}")
    finally:
        if 'conn' in locals() and conn.is_connected():
            cursor.close()
            conn.close()
    return render_template('admin/appointments.html', appointments=appointments)

@app.route('/admin/appointments/update/<int:appointment_id>', methods=['POST'])
@admin_required
def admin_update_appointment(appointment_id):
    new_status = request.form.get('status')
    new_date = request.form.get('preferred_date')
    new_time = request.form.get('preferred_time')
    try:
        conn = db_pool.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE appointments SET status = %s, preferred_date = %s, preferred_time = %s WHERE id = %s",
            (new_status, new_date, new_time, appointment_id)
        )
        conn.commit()
        log_event('INFO', f"Admin updated appointment ID {appointment_id} to status '{new_status}', date '{new_date}', and time '{new_time}'.")
    except mysql.connector.Error as err:
        log_event('ERROR', f"Failed to update appointment ID {appointment_id}: {err}")
    finally:
        if 'conn' in locals() and conn.is_connected():
            cursor.close()
            conn.close()
    return redirect(url_for('admin_appointments'))

@app.route('/admin/subscribers')
@admin_required
def admin_subscribers():
    subscribers = []
    try:
        conn = db_pool.get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM subscribers ORDER BY subscribed_at DESC")
        subscribers = cursor.fetchall()
    except mysql.connector.Error as err:
        flash("Could not retrieve subscribers.", "error")
    finally:
        if 'conn' in locals() and conn.is_connected():
            cursor.close()
            conn.close()
    return render_template('admin/subscribers.html', subscribers=subscribers)

@app.route('/submit_contact', methods=['POST'])
def submit_contact():
    # Ensure user is logged in to submit a message
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please log in to contact us.'}), 401

    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    phone_number = data.get('phone') # Get the phone number
    message = data.get('message')

    if not name or not email or not message:
        return jsonify({'success': False, 'message': 'Please fill out all fields.'})

    try:
        conn = db_pool.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO contacts (name, email, phone_number, message) VALUES (%s, %s, %s, %s)",
            (name, email, phone_number, message)
        )
        conn.commit()
        return jsonify({'success': True, 'message': 'Thank you! Your message has been sent.'})
    except mysql.connector.Error as err:
        print(f"Database Error on contact submission: {err}")
        return jsonify({'success': False, 'message': 'A server error occurred. Please try again later.'})
    finally:
        if 'conn' in locals() and conn.is_connected():
            cursor.close()
            conn.close()

# Add other routes like /profile, /blogs, etc. here

if __name__ == '__main__':
    app.run(debug=True)
