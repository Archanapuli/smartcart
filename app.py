# app.py
# ---------------------------------------------------------
#  Admin Signup + OTP + Password Hash
# ---------------------------------------------------------

from flask import Flask, render_template, request, redirect, session, flash,url_for,make_response
from flask_mail import Mail, Message
import sqlite3
import bcrypt
import random
import config
import os
import razorpay
import traceback
from utils.pdf_generator import generate_pdf
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
load_dotenv()


app = Flask(__name__)
app.secret_key = config.SECRET_KEY

razorpay_client = razorpay.Client(auth=(config.RAZORPAY_KEY_ID, config.RAZORPAY_KEY_SECRET))


# ---------------- EMAIL CONFIGURATION ----------------
app.config['MAIL_SERVER'] = config.MAIL_SERVER
app.config['MAIL_PORT'] = config.MAIL_PORT
app.config['MAIL_USE_TLS'] = config.MAIL_USE_TLS
app.config['MAIL_USERNAME'] = config.MAIL_USERNAME
app.config['MAIL_PASSWORD'] = config.MAIL_PASSWORD
app.config['MAIL_DEFAULT_SENDER'] = config.MAIL_DEFAULT_SENDER

mail = Mail(app)


# ---------------- DB CONNECTION FUNCTION --------------

def get_db_connection():
    conn = sqlite3.connect('smartcart.db')
    conn.row_factory = sqlite3.Row  # allows dict-like access
    return conn

# ---------------------------------------------------------
# ROUTE 1: ADMIN SIGNUP (SEND OTP) - SQLITE3
# ---------------------------------------------------------
@app.route('/admin-signup', methods=['GET', 'POST'])
def admin_signup():

    # Show form
    if request.method == "GET":
        return render_template("admin/admin_signup.html")

    # POST → Process signup
    name = request.form['name']
    email = request.form['email']

    # Check if admin email already exists (SQLite)
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT admin_id FROM admin WHERE email = ?", (email,))
    existing_admin = cursor.fetchone()
    conn.close()

    if existing_admin:
        flash("This email is already registered. Please login instead.", "danger")
        return redirect('/admin-signup')

    # Save user input temporarily in session
    session['signup_name'] = name
    session['signup_email'] = email

    # Generate OTP and store in session
    otp = random.randint(100000, 999999)
    session['otp'] = otp

    # Send OTP Email
    message = Message(
        subject="SmartCart Admin OTP",
        sender=config.MAIL_USERNAME,
        recipients=[email]
    )
    message.body = f"Your OTP for SmartCart Admin Registration is: {otp}"
    mail.send(message)

    flash("OTP sent to your email!", "success")
    return redirect('/verify-otp')


# ---------------------------------------------------------
# ROUTE 3: VERIFY OTP + SAVE ADMIN (SQLite3)
# ---------------------------------------------------------
@app.route('/verify-otp', methods=['GET','POST'])
def verify_otp():
    if request.method == 'GET':
        return render_template("admin/verify_otp.html")
    
    # User submitted OTP + Password
    user_otp = request.form['otp']
    password = request.form['password']

    # Compare OTP
    if str(session.get('otp')) != str(user_otp):
        flash("Invalid OTP. Try again!", "danger")
        return redirect('/verify-otp')

    # Hash password using bcrypt
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    hashed_password_str = hashed_password.decode('utf-8')  # store as text

    # Insert admin into SQLite database
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        'INSERT INTO "admin" (name, email, password) VALUES (?, ?, ?)',
        (session['signup_name'], session['signup_email'], hashed_password_str)
    )
    conn.commit()
    cursor.close()
    conn.close()

    # Clear temporary session data
    session.pop('otp', None)
    session.pop('signup_name', None)
    session.pop('signup_email', None)

    flash("Admin Registered Successfully!", "success")
    return redirect('/admin-login')

# ------------------------------
# ROUTE 4: ADMIN LOGIN (SQLite3)
# ------------------------------
@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():

    # Show login page
    if request.method == 'GET':
        session.pop('admin_id', None)
        return render_template("admin/admin_login.html")

    # POST → Validate login
    email = request.form['email']
    password = request.form['password']

    # Step 1: Check if admin email exists
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row  # allows dict-like access
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM "admin" WHERE email = ?', (email,))
    admin = cursor.fetchone()

    cursor.close()
    conn.close()

    if admin is None:
        flash("Email not found! Please register first.", "danger")
        return redirect('/admin-login')

    # Step 2: Compare entered password with hashed password
    stored_hashed_password = admin['password'].encode('utf-8')

    if not bcrypt.checkpw(password.encode('utf-8'), stored_hashed_password):
        flash("Incorrect password! Try again.", "danger")
        return redirect('/admin-login')

    # Step 3: If login success → Create admin session
    session['admin_id'] = admin['admin_id']
    session['admin_name'] = admin['name']
    session['admin_email'] = admin['email']

    flash("Login Successful!", "success")
    return redirect('/admin-dashboard')


# ------------------------------
# ROUTE 5: ADMIN DASHBOARD
# ------------------------------
@app.route('/admin-dashboard')
def admin_dashboard():

    # Protect dashboard → Only logged-in admin can access
    if 'admin_id' not in session:
        flash("Please login to access dashboard!", "danger")
        return redirect('/admin-login')

    # Send admin name to dashboard UI
    return render_template("admin/dashboard.html", admin_name=session['admin_name'])


# ------------------------------
# ROUTE 6: ADMIN LOGOUT
# ------------------------------
@app.route('/admin-logout')
def admin_logout():

    # Clear admin session
    session.pop('admin_id', None)
    session.pop('admin_name', None)
    session.pop('admin_email', None)

    flash("Logged out successfully.", "success")
    return redirect('/admin-login')


# ------------------- IMAGE UPLOAD PATH -------------------
UPLOAD_FOLDER = 'static/uploads/product_images'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


# ========================================================
# ROUTE 7: SHOW ADD PRODUCT PAGE (Protected Route)
# ========================================================
@app.route('/admin/add-item', methods=['GET'])
def add_item_page():

    # Only logged-in admin can access
    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    return render_template("admin/add_item.html")


# ========================================================
# ROUTE 8: ADD PRODUCT INTO DATABASE (SQLite3)
# ========================================================
@app.route('/admin/add-item', methods=['POST'])
def add_item():

    # Check admin session
    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    # 1️⃣ Get form data
    name = request.form['name']
    description = request.form['description']
    category = request.form['category']
    price = request.form['price']
    image_file = request.files['image']

    # 2️⃣ Validate image upload
    if image_file.filename == "":
        flash("Please upload a product image!", "danger")
        return redirect('/admin/add-item')

    # 3️⃣ Secure the file name
    filename = secure_filename(image_file.filename)

    # 4️⃣ Create full path
    image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    # 5️⃣ Save image into folder
    image_file.save(image_path)

    # 6️⃣ Insert product into SQLite database
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        'INSERT INTO "products" (name, description, category, price, image) VALUES (?, ?, ?, ?, ?)',
        (name, description, category, price, filename)
    )

    conn.commit()
    cursor.close()
    conn.close()

    flash("Product added successfully!", "success")
    return redirect('/admin/add-item')

# =======================================================
# ROUTE 10: VIEW SINGLE PRODUCT DETAILS (SQLite3)
# =======================================================
@app.route('/admin/view-item/<int:item_id>')
def view_item(item_id):

    # Check admin session
    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    conn = get_db_connection()
    conn.row_factory = sqlite3.Row  # allows dict-like access
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM "products" WHERE product_id = ?', (item_id,))
    product = cursor.fetchone()

    cursor.close()
    conn.close()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/admin/item-list')

    return render_template("admin/view_item.html", product=product)


# =======================================================
# ROUTE 11: SHOW UPDATE FORM WITH EXISTING DATA (SQLite3)
# =======================================================
@app.route('/admin/update-item/<int:item_id>', methods=['GET'])
def update_item_page(item_id):

    # Check login
    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    # Fetch product data
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row  # allows dict-like access
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM "products" WHERE product_id = ?', (item_id,))
    product = cursor.fetchone()

    cursor.close()
    conn.close()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/admin/item-list')

    return render_template("admin/update_item.html", product=product)


# =======================================================
# ROUTE 12: UPDATE PRODUCT + OPTIONAL IMAGE REPLACE (SQLite3)
# =======================================================
@app.route('/admin/update-item/<int:item_id>', methods=['POST'])
def update_item(item_id):

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    # 1️⃣ Get updated form data
    name = request.form['name']
    description = request.form['description']
    category = request.form['category']
    price = request.form['price']
    new_image = request.files['image']

    # 2️⃣ Fetch old product data
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM "products" WHERE product_id = ?', (item_id,))
    product = cursor.fetchone()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/admin/item-list')

    old_image_name = product['image']

    # 3️⃣ If admin uploaded a new image → replace it
    if new_image and new_image.filename != "":
        new_filename = secure_filename(new_image.filename)
        new_image_path = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)
        new_image.save(new_image_path)

        # Delete old image
        old_image_path = os.path.join(app.config['UPLOAD_FOLDER'], old_image_name)
        if old_image_name and os.path.exists(old_image_path):
            os.remove(old_image_path)

        final_image_name = new_filename
    else:
        final_image_name = old_image_name

    # 4️⃣ Update product in SQLite
    cursor.execute("""
        UPDATE "products"
        SET name = ?, description = ?, category = ?, price = ?, image = ?
        WHERE product_id = ?
    """, (name, description, category, price, final_image_name, item_id))

    conn.commit()
    cursor.close()
    conn.close()

    flash("Product updated successfully!", "success")
    return redirect('/admin/item-list')


# =======================================================
# ROUTE 13: UPDATED PRODUCT LIST WITH SEARCH + CATEGORY FILTER (SQLite3)
# =======================================================
@app.route('/admin/item-list')
def item_list():

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    search = request.args.get('search', '')
    category_filter = request.args.get('category', '')

    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # 1️⃣ Fetch category list for dropdown
    cursor.execute('SELECT DISTINCT category FROM "products"')
    categories = cursor.fetchall()

    # 2️⃣ Build dynamic query based on filters
    query = 'SELECT * FROM "products" WHERE 1=1'
    params = []

    if search:
        query += ' AND name LIKE ?'
        params.append(f"%{search}%")

    if category_filter:
        query += ' AND category = ?'
        params.append(category_filter)

    cursor.execute(query, params)
    products = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        "admin/item_list.html",
        products=products,
        categories=categories
    )


# =======================================================
# DELETE PRODUCT (DELETE DB ROW + DELETE IMAGE FILE) - SQLite3
# =======================================================
@app.route('/admin/delete-item/<int:item_id>')
def delete_item(item_id):

    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # 1️⃣ Fetch product to get image name
    cursor.execute('SELECT image FROM "products" WHERE product_id = ?', (item_id,))
    product = cursor.fetchone()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/admin/item-list')

    image_name = product['image']

    # Delete image from folder
    image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_name)
    if image_name and os.path.exists(image_path):
        os.remove(image_path)

    # 2️⃣ Delete product from DB
    cursor.execute('DELETE FROM "products" WHERE product_id = ?', (item_id,))
    conn.commit()

    cursor.close()
    conn.close()

    flash("Product deleted successfully!", "success")
    return redirect('/admin/item-list')


ADMIN_UPLOAD_FOLDER = 'static/uploads/admin_profiles'
app.config['ADMIN_UPLOAD_FOLDER'] = ADMIN_UPLOAD_FOLDER

# =======================================================
# ROUTE 15: SHOW ADMIN PROFILE DATA - SQLite3
# =======================================================
@app.route('/admin/profile', methods=['GET'])
def admin_profile():

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM "admin" WHERE admin_id = ?', (admin_id,))
    admin = cursor.fetchone()

    cursor.close()
    conn.close()

    return render_template("admin/admin_profile.html", admin=admin)


# =======================================================
# ROUTE 16: UPDATE ADMIN PROFILE (SQLite3)
# =======================================================
@app.route('/admin/profile', methods=['POST'])
def admin_profile_update():

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    # 1️⃣ Get form data
    name = request.form.get('name')
    email = request.form.get('email')
    new_password = request.form.get('password')
    new_image = request.files.get('profile_image')

    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # 2️⃣ Fetch old admin data
    cursor.execute('SELECT * FROM "admin" WHERE admin_id = ?', (admin_id,))
    admin = cursor.fetchone()

    old_image_name = admin['profile_image']

    # 3️⃣ Update password only if entered
    if new_password:
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        hashed_password_str = hashed_password.decode('utf-8')
    else:
        hashed_password_str = admin['password']  # keep old password

    # 4️⃣ Process new profile image if uploaded
    if new_image and new_image.filename != "":
        new_filename = secure_filename(new_image.filename)
        image_path = os.path.join(app.config['ADMIN_UPLOAD_FOLDER'], new_filename)
        new_image.save(image_path)

        # Delete old image
        if old_image_name:
            old_image_path = os.path.join(app.config['ADMIN_UPLOAD_FOLDER'], old_image_name)
            if os.path.exists(old_image_path):
                os.remove(old_image_path)

        final_image_name = new_filename
    else:
        final_image_name = old_image_name

    # 5️⃣ Update database
    cursor.execute("""
        UPDATE "admin"
        SET name = ?, email = ?, password = ?, profile_image = ?
        WHERE admin_id = ?
    """, (name, email, hashed_password_str, final_image_name, admin_id))

    conn.commit()
    cursor.close()
    conn.close()

    # Update session for UI
    session['admin_name'] = name  
    session['admin_email'] = email

    flash("Profile updated successfully!", "success")
    return redirect('/admin/profile')


# =======================================================
# ROUTE: DELETE ADMIN PROFILE IMAGE (SQLite3)
# =======================================================
@app.route('/admin/delete-profile-image', methods=['POST'])
def delete_admin_profile_image():

    if 'admin_id' not in session:
        flash("Please login first", "danger")
        return redirect(url_for('admin_login'))

    admin_id = session['admin_id']

    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Get current image
    cursor.execute('SELECT profile_image FROM "admin" WHERE admin_id = ?', (admin_id,))
    admin = cursor.fetchone()

    if admin and admin['profile_image']:
        image_path = os.path.join(app.config['ADMIN_UPLOAD_FOLDER'], admin['profile_image'])

        # Delete file if exists
        if os.path.exists(image_path):
            os.remove(image_path)

        # Remove from DB
        cursor.execute('UPDATE "admin" SET profile_image = NULL WHERE admin_id = ?', (admin_id,))
        conn.commit()

        flash("Profile photo deleted successfully", "success")

    cursor.close()
    conn.close()

    return redirect(url_for('admin_profile'))


# ==========================================================
# ROUTE: FORGOT PASSWORD (SEND OTP) - SQLite3
# ==========================================================
@app.route('/admin-forgot-password', methods=['GET', 'POST'])
def admin_forgot_password():

    if request.method == 'GET':
        return render_template("admin/admin_forgot_password.html")

    email = request.form['email']

    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM "admin" WHERE email = ?', (email,))
    admin = cursor.fetchone()

    cursor.close()
    conn.close()

    if not admin:
        flash("Email not registered!", "danger")
        return redirect('/admin-forgot-password')

    # Generate OTP
    otp = random.randint(100000, 999999)

    # Store in session
    session['reset_otp'] = otp
    session['reset_email'] = email

    # Send Email
    message = Message(
        subject="SmartCart Password Reset OTP",
        sender=config.MAIL_USERNAME,
        recipients=[email]
    )
    message.body = f"Your OTP for password reset is: {otp}"
    mail.send(message)

    flash("OTP sent to your email!", "success")
    return redirect('/admin-reset-password')


# ==========================================================
# ROUTE: VERIFY OTP + RESET PASSWORD - SQLite3
# ==========================================================
@app.route('/admin-reset-password', methods=['GET', 'POST'])
def admin_reset_password():

    if request.method == 'GET':
        return render_template("admin/admin_reset_password.html")

    user_otp = request.form['otp']
    new_password = request.form['password']

    # Check OTP
    if str(session.get('reset_otp')) != str(user_otp):
        flash("Invalid OTP!", "danger")
        return redirect('/admin-reset-password')

    email = session.get('reset_email')

    # Hash new password
    hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
    hashed_password_str = hashed_password.decode('utf-8')

    # Update password in SQLite
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('UPDATE "admin" SET password = ? WHERE email = ?', (hashed_password_str, email))
    conn.commit()
    cursor.close()
    conn.close()

    # Clear session
    session.pop('reset_otp', None)
    session.pop('reset_email', None)

    flash("Password reset successful! Please login.", "success")
    return redirect('/admin-login')


# ================================================================
# ADMIN: VIEW ALL ORDERS - SQLite3
# ================================================================
@app.route('/admin/orders')
def admin_orders():

    if 'admin_id' not in session:
        flash("Please login as admin!", "danger")
        return redirect('/admin-login')

    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("""
        SELECT o.order_id, o.user_id, o.amount, 
               o.payment_status, o.order_status, o.created_at,
               u.username AS username
        FROM "orders" o
        LEFT JOIN "users" u ON o.user_id = u.user_id
        ORDER BY o.created_at DESC
    """)

    orders = cursor.fetchall()
    cursor.close()
    conn.close()

    return render_template("admin/order_list.html", orders=orders)


# ================================================================
# ADMIN: VIEW ORDER DETAILS - SQLite3
# ================================================================
@app.route('/admin/order/<int:order_id>')
def admin_order_details(order_id):

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM "orders" WHERE order_id = ?', (order_id,))
    order = cursor.fetchone()

    cursor.execute('SELECT * FROM "order_items" WHERE order_id = ?', (order_id,))
    items = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template("admin/order_details.html", order=order, items=items)


# ================================================================
# ADMIN: UPDATE ORDER STATUS - SQLite3
# ================================================================
@app.route("/admin/update-order-status/<int:order_id>", methods=['GET','POST'])
def update_order_status(order_id):
    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    new_status = request.form.get('status')

    conn = get_db_connection()
    cursor = conn.cursor()

    # SQLite3 query with ? placeholders
    cursor.execute('UPDATE "orders" SET order_status = ? WHERE order_id = ?', 
                   (new_status, order_id))

    conn.commit()
    cursor.close()
    conn.close()

    flash("Order status updated successfully!", "success")
    return redirect(f"/admin/order/{order_id}")

#ROUTE 1: User Registration (GET + POST)
# =================================================================
# ROUTE: USER REGISTRATION
# =================================================================


@app.route('/user-register', methods=['GET', 'POST'])
def user_register():

    if request.method == 'GET':
        return render_template("user/user_register.html")

    first_name = request.form['first_name']
    last_name = request.form['last_name']
    username = request.form['username']
    email = request.form['email']

    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Check if email exists
    cursor.execute('SELECT * FROM "users" WHERE email = ?', (email,))
    if cursor.fetchone():
        flash("Email already registered!", "danger")
        cursor.close()
        conn.close()
        return redirect('/user-register')

    # Check if username exists
    cursor.execute('SELECT * FROM "users" WHERE username = ?', (username,))
    if cursor.fetchone():
        flash("Username already taken!", "danger")
        cursor.close()
        conn.close()
        return redirect('/user-register')

    cursor.close()
    conn.close()

    # Generate OTP
    otp = str(random.randint(100000, 999999))
    print("OTP:", otp)  # Replace with email sending later

    # Store temporary data in session
    session['temp_user'] = {
        "first_name": first_name,
        "last_name": last_name,
        "username": username,
        "email": email
    }
    session['otp'] = otp

    # Send OTP Email
    msg = Message(
        subject="Your OTP Verification Code",
        recipients=[email]
    )
    msg.body = f"Your OTP code is: {otp}"
    mail.send(msg)

    flash("OTP sent to your email!", "success")
    return redirect('/user-verify-otp')


@app.route('/user-verify-otp', methods=['GET', 'POST'])
def user_verify_otp():

    if request.method == 'GET':
        return render_template("user/verify_otp.html")

    # Get form data
    entered_otp = request.form.get('otp')
    password = request.form.get('password')
    confirm_password = request.form.get('confirm_password')

    # 1️⃣ Validate OTP session
    session_otp = session.get('otp')
    if not session_otp:
        flash("Session expired. Please register again.", "danger")
        return redirect('/user-register')

    if str(entered_otp).strip() != str(session_otp).strip():
        flash("Invalid OTP!", "danger")
        return redirect('/user-verify-otp')

    # 2️⃣ Check password confirmation
    if password != confirm_password:
        flash("Passwords do not match!", "danger")
        return redirect('/user-verify-otp')

    # 3️⃣ Check temp_user session
    temp_user = session.get('temp_user')
    if not temp_user:
        flash("Session expired. Please register again.", "danger")
        return redirect('/user-register')

    # 4️⃣ Hash password
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    hashed_password_str = hashed_password.decode('utf-8')

    # 5️⃣ Insert user into SQLite3 DB
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO "users" 
        (first_name, last_name, username, email, password)
        VALUES (?, ?, ?, ?, ?)
    """, (
        temp_user['first_name'],
        temp_user['last_name'],
        temp_user['username'],
        temp_user['email'],
        hashed_password_str
    ))

    conn.commit()
    cursor.close()
    conn.close()

    # 6️⃣ Clear session
    session.pop('temp_user', None)
    session.pop('otp', None)

    flash("Account created successfully! Please login.", "success")
    return redirect('/user-login')


# ==========================================================
# USER LOGIN (GET + POST) - SQLite3
# ==========================================================
@app.route('/user-login', methods=['GET', 'POST'])
def user_login():

    if request.method == 'GET':
        return render_template("user/user_login.html")

    email = request.form.get('email')
    password = request.form.get('password')

    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM "users" WHERE email = ?', (email,))
    user = cursor.fetchone()

    cursor.close()
    conn.close()

    if not user:
        flash("Email not found! Please register.", "danger")
        return redirect('/user-login')

    # Verify password
    if not bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
        flash("Incorrect password!", "danger")
        return redirect('/user-login')

    # Create user session
    session['user_id'] = user['user_id']
    session['user_name'] = f"{user['first_name']} {user['last_name']}"
    session['user_email'] = user['email']

    flash("Login successful!", "success")
    return redirect('/user-dashboard')


# ==========================================================
# USER FORGOT PASSWORD (SEND OTP) - SQLite3
# ==========================================================
@app.route('/user-forgot-password', methods=['GET', 'POST'])
def user_forgot_password():

    if request.method == 'GET':
        return render_template("user/user_forgot_password.html")

    email = request.form.get('email')

    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM "users" WHERE email = ?', (email,))
    user = cursor.fetchone()

    cursor.close()
    conn.close()

    if not user:
        flash("Email not registered!", "danger")
        return redirect('/user-forgot-password')

    # Generate OTP
    otp = random.randint(100000, 999999)

    # Store in session
    session['reset_otp'] = otp
    session['reset_email'] = email

    # Send Email
    message = Message(
        subject="SmartCart Password Reset OTP",
        sender=config.MAIL_USERNAME,
        recipients=[email]
    )
    message.body = f"Your OTP for password reset is: {otp}"
    mail.send(message)

    flash("OTP sent to your email!", "success")
    return redirect('/user-reset-password')


# ==========================================================
# USER RESET PASSWORD (VERIFY OTP + UPDATE) - SQLite3
# ==========================================================
@app.route('/user-reset-password', methods=['GET', 'POST'])
def user_reset_password():

    if request.method == 'GET':
        return render_template("user/user_reset_password.html")

    user_otp = request.form.get('otp')
    new_password = request.form.get('password')

    # Check OTP
    session_otp = session.get('reset_otp')
    if not session_otp or str(user_otp).strip() != str(session_otp).strip():
        flash("Invalid OTP!", "danger")
        return redirect('/user-reset-password')

    email = session.get('reset_email')

    # Hash new password
    hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
    hashed_password_str = hashed_password.decode('utf-8')

    # Update password in SQLite3
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('UPDATE "users" SET password = ? WHERE email = ?', 
                   (hashed_password_str, email))
    conn.commit()
    cursor.close()
    conn.close()

    # Clear session
    session.pop('reset_otp', None)
    session.pop('reset_email', None)

    flash("Password reset successful! Please login.", "success")
    return redirect('/user-login')


# ==========================================================
# USER DASHBOARD - SHOW PRODUCTS
# ==========================================================
@app.route('/user-dashboard')
def user_dashboard():

    if 'user_id' not in session:
        return redirect('/user-login')

    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM "products"')
    products = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template("user/user_home.html", products=products)


# ==========================================================
# USER LOGOUT
# ==========================================================
@app.route('/user-logout')
def user_logout():

    session.pop('user_id', None)
    session.pop('user_name', None)
    session.pop('user_email', None)

    flash("Logged out successfully!", "success")
    return redirect('/user-login')

USER_UPLOAD_FOLDER = 'static/uploads/user_profiles'
app.config['USER_UPLOAD_FOLDER'] = USER_UPLOAD_FOLDER


# ==========================================================
# USER PROFILE (GET)
# ==========================================================
@app.route('/user/profile', methods=['GET'])
def user_profile():

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    user_id = session['user_id']

    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM "users" WHERE user_id = ?', (user_id,))
    user = cursor.fetchone()

    cursor.close()
    conn.close()

    return render_template("user/user_profile.html", user=user)


# ==========================================================
# USER PROFILE UPDATE (POST)
# ==========================================================
@app.route('/user/profile', methods=['POST'])
def user_profile_update():

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    user_id = session['user_id']

    # 1️⃣ Get form data
    name = request.form.get('name')
    email = request.form.get('email')
    new_password = request.form.get('password')
    new_image = request.files.get('profile_image')

    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # 2️⃣ Fetch old user data
    cursor.execute('SELECT * FROM "users" WHERE user_id = ?', (user_id,))
    user = cursor.fetchone()

    old_image_name = user['profile_image']

    # 3️⃣ Update password only if entered
    if new_password:
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        hashed_password_str = hashed_password.decode('utf-8')
    else:
        hashed_password_str = user['password']  # keep old password

    # 4️⃣ Process new profile image if uploaded
    if new_image and new_image.filename != "":

        from werkzeug.utils import secure_filename
        new_filename = secure_filename(new_image.filename)

        # Save new image
        image_path = os.path.join(app.config['USER_UPLOAD_FOLDER'], new_filename)
        new_image.save(image_path)

        # Delete old image
        if old_image_name:
            old_image_path = os.path.join(app.config['USER_UPLOAD_FOLDER'], old_image_name)
            if os.path.exists(old_image_path):
                os.remove(old_image_path)

        final_image_name = new_filename
    else:
        final_image_name = old_image_name

    # 5️⃣ Update database
    cursor.execute("""
        UPDATE "users"
        SET name = ?, email = ?, password = ?, profile_image = ?
        WHERE user_id = ?
    """, (name, email, hashed_password_str, final_image_name, user_id))

    conn.commit()
    cursor.close()
    conn.close()

    # Update session for UI consistency
    session['user_name'] = name
    session['user_email'] = email

    flash("Profile updated successfully!", "success")
    return redirect('/user/profile')


#=====================================================
# ROUTE: TO DELETE USER PROFILE IMAGE (SQLite3)
#======================================================
@app.route('/user/delete-profile-image', methods=['POST'])
def delete_user_profile_image():

    if 'user_id' not in session:
        flash("Please login first", "danger")
        return redirect(url_for('user_login'))

    user_id = session['user_id']

    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Get current image
    cursor.execute(
        'SELECT profile_image FROM "users" WHERE user_id = ?', (user_id,))
    user = cursor.fetchone()

    if user and user['profile_image']:
        image_path = os.path.join(
            app.root_path,
            'static',
            'uploads',
            'user_profiles',
            user['profile_image']
        )

        # Delete file if exists
        if os.path.exists(image_path):
            os.remove(image_path)

        # Remove from DB
        cursor.execute(
            'UPDATE "users" SET profile_image = NULL WHERE user_id = ?', (user_id,))
        conn.commit()

        flash("Profile photo deleted successfully", "success")

    cursor.close()
    conn.close()

    return redirect(url_for('user_profile'))


# ==========================================================
# ROUTE 5: Display All Products for Users (SEARCH + FILTER)
# ==========================================================
@app.route('/user/products')
def user_products():

    if 'user_id' not in session:
        flash("Please login to view products!", "danger")
        return redirect('/user-login')

    search = request.args.get('search', '')
    category_filter = request.args.get('category', '')

    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Fetch categories for filter dropdown
    cursor.execute('SELECT DISTINCT category FROM "products"')
    categories = cursor.fetchall()

    # Build dynamic SQL
    query = 'SELECT * FROM "products" WHERE 1=1'
    params = []

    if search:
        query += ' AND name LIKE ?'
        params.append(f'%{search}%')

    if category_filter:
        query += ' AND category = ?'
        params.append(category_filter)

    cursor.execute(query, params)
    products = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        "user/user_products.html",
        products=products,
        categories=categories
    )


# ==========================================================
# ROUTE 6: Single Product Details Page (SQLite3)
# ==========================================================
@app.route('/user/product/<int:product_id>')
def user_product_details(product_id):

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM "products" WHERE product_id = ?', (product_id,))
    product = cursor.fetchone()

    cursor.close()
    conn.close()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/user/products')

    return render_template("user/product_details.html", product=product)

# =========================================================
# ROUTE 7: Add to Cart (SQLite3)
# =========================================================
@app.route('/user/add-to-cart/<int:product_id>')
def add_to_cart(product_id):

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    # Create cart if doesn't exist
    if 'cart' not in session:
        session['cart'] = {}

    cart = session['cart']

    # Get product from SQLite3
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM "products" WHERE product_id = ?', (product_id,))
    product = cursor.fetchone()
    cursor.close()
    conn.close()

    if not product:
        flash("Product not found.", "danger")
        return redirect(request.referrer)

    pid = str(product_id)

    # If exists → increase quantity
    if pid in cart:
        cart[pid]['quantity'] += 1
    else:
        cart[pid] = {
            'name': product['name'],
            'price': float(product['price']),
            'image': product['image'],
            'quantity': 1
        }

    session['cart'] = cart

    flash("Item added to cart!", "success")
    return redirect(request.referrer)  # Return to same page


# =========================================================
# ROUTE 8: View Cart Page
# =========================================================
@app.route('/user/cart')
def view_cart():

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    cart = session.get('cart', {})

    # Calculate total
    grand_total = sum(item['price'] * item['quantity'] for item in cart.values())

    return render_template("user/cart.html", cart=cart, grand_total=grand_total)


# =========================================================
# ROUTE 9: Increase Quantity
# =========================================================
@app.route('/user/cart/increase/<pid>')
def increase_quantity(pid):

    cart = session.get('cart', {})

    if pid in cart:
        cart[pid]['quantity'] += 1

    session['cart'] = cart
    return redirect('/user/cart')


# =========================================================
# ROUTE 10: Decrease Quantity
# =========================================================
@app.route('/user/cart/decrease/<pid>')
def decrease_quantity(pid):

    cart = session.get('cart', {})

    if pid in cart:
        cart[pid]['quantity'] -= 1

        # If quantity becomes 0 → remove item
        if cart[pid]['quantity'] <= 0:
            cart.pop(pid)

    session['cart'] = cart
    return redirect('/user/cart')


# =========================================================
# ROUTE 11: Remove Item Completely
# =========================================================
@app.route('/user/cart/remove/<pid>')
def remove_from_cart(pid):

    cart = session.get('cart', {})

    if pid in cart:
        cart.pop(pid)

    session['cart'] = cart

    flash("Item removed!", "success")
    return redirect('/user/cart')

# =================================================================
# ROUTE: CREATE RAZORPAY ORDER
# =================================================================
@app.route('/user/pay')
def user_pay():

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    cart = session.get('cart', {})

    if not cart:
        flash("Your cart is empty!", "danger")
        return redirect('/user/products')

    # Calculate total amount
    total_amount = sum(item['price'] * item['quantity'] for item in cart.values())
    razorpay_amount = int(total_amount * 100)  # convert to paise

    # Create Razorpay order
    razorpay_order = razorpay_client.order.create({
        "amount": razorpay_amount,
        "currency": "INR",
        "payment_capture": "1"
    })

    session['razorpay_order_id'] = razorpay_order['id']

    # Send order details to frontend
    return render_template(
        "user/payment.html",
        amount=total_amount,
        key_id=config.RAZORPAY_KEY_ID,
        order_id=razorpay_order['id']
    )


# =================================================================
# TEMP SUCCESS PAGE (Verification in Day 13)
# =================================================================
@app.route('/payment-success')
def payment_success():

    payment_id = request.args.get('payment_id')
    order_id = request.args.get('order_id')

    if not payment_id:
        flash("Payment failed!", "danger")
        return redirect('/user/cart')

    return render_template(
        "user/payment_success.html",
        payment_id=payment_id,
        order_id=order_id
    )


# ------------------------------
# Route: Verify Payment and Store Order (SQLite3)
# ------------------------------
@app.route('/verify-payment', methods=['POST'])
def verify_payment():
    if 'user_id' not in session:
        flash("Please login to complete the payment.", "danger")
        return redirect('/user-login')

    # Read values posted from frontend
    razorpay_payment_id = request.form.get('razorpay_payment_id')
    razorpay_order_id = request.form.get('razorpay_order_id')
    razorpay_signature = request.form.get('razorpay_signature')

    if not (razorpay_payment_id and razorpay_order_id and razorpay_signature):
        flash("Payment verification failed (missing data).", "danger")
        return redirect('/user/cart')

    # Build verification payload required by Razorpay client.utility
    payload = {
        'razorpay_order_id': razorpay_order_id,
        'razorpay_payment_id': razorpay_payment_id,
        'razorpay_signature': razorpay_signature
    }

    try:
        # This will raise an error if signature invalid
        razorpay_client.utility.verify_payment_signature(payload)
    except Exception as e:
        app.logger.error("Razorpay signature verification failed: %s", str(e))
        flash("Payment verification failed. Please contact support.", "danger")
        return redirect('/user/cart')

    user_id = session['user_id']
    cart = session.get('cart', {})

    if not cart:
        flash("Cart is empty. Cannot create order.", "danger")
        return redirect('/user/products')

    total_amount = sum(item['price'] * item['quantity'] for item in cart.values())

    # SQLite3 connection
    conn = sqlite3.connect('smartcart.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    try:
        # Insert into orders table
        cursor.execute("""
            INSERT INTO orders (user_id, razorpay_order_id, razorpay_payment_id, amount, payment_status)
            VALUES (?, ?, ?, ?, ?)
        """, (user_id, razorpay_order_id, razorpay_payment_id, total_amount, 'paid'))

        order_db_id = cursor.lastrowid  # newly created order's primary key

        # Insert all items
        for pid_str, item in cart.items():
            product_id = int(pid_str)
            cursor.execute("""
                INSERT INTO order_items (order_id, product_id, product_name, quantity, price)
                VALUES (?, ?, ?, ?, ?)
            """, (order_db_id, product_id, item['name'], item['quantity'], item['price']))

        conn.commit()

        # Clear cart and temporary razorpay order id
        session.pop('cart', None)
        session.pop('razorpay_order_id', None)

        flash("Payment successful and order placed!", "success")
        return redirect(f"/user/order-success/{order_db_id}")

    except Exception as e:
        conn.rollback()
        app.logger.error("Order storage failed: %s\n%s", str(e), traceback.format_exc())
        flash("There was an error saving your order. Contact support.", "danger")
        return redirect('/user/cart')

    finally:
        cursor.close()
        conn.close()



#================================ 
# Route: Order Success Page
#================================
@app.route('/user/order-success/<int:order_db_id>')
def order_success(order_db_id):
    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    conn.row_factory = sqlite3.Row  # Access columns by name
    cursor = conn.cursor()

    # Fetch order
    cursor.execute("SELECT * FROM orders WHERE order_id=? AND user_id=?", 
                   (order_db_id, session['user_id']))
    order = cursor.fetchone()

    # Fetch order items
    cursor.execute("SELECT * FROM order_items WHERE order_id=?", (order_db_id,))
    items = cursor.fetchall()

    cursor.close()
    conn.close()

    if not order:
        flash("Order not found.", "danger")
        return redirect('/user/products')

    return render_template("user/order_success.html", order=order, items=items)


#================================ 
# My Orders Page (List user's orders)
#================================
@app.route('/user/my-orders')
def my_orders():
    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    conn.row_factory = sqlite3.Row  # Access columns by name
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM orders WHERE user_id=? ORDER BY created_at DESC", 
                   (session['user_id'],))
    orders = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template("user/my_orders.html", orders=orders)

# ----------------------------
# GENERATE INVOICE PDF
# ----------------------------
@app.route("/user/download-invoice/<int:order_id>")
def download_invoice(order_id):

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    # Fetch order
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row  # Access columns by name
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM orders WHERE order_id=? AND user_id=?",
        (order_id, session['user_id'])
    )
    order = cursor.fetchone()

    cursor.execute(
        "SELECT * FROM order_items WHERE order_id=?",
        (order_id,)
    )
    items = cursor.fetchall()

    cursor.close()
    conn.close()

    if not order:
        flash("Order not found.", "danger")
        return redirect('/user/my-orders')

    # Render invoice HTML
    html = render_template("user/invoice.html", order=order, items=items)

    pdf = generate_pdf(html)
    if not pdf:
        flash("Error generating PDF", "danger")
        return redirect('/user/my-orders')

    # Prepare response
    response = make_response(pdf.getvalue())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f"attachment; filename=invoice_{order_id}.pdf"

    return response

# =====================================
# ROUTE: HELP CENTER
# =====================================
@app.route('/help-center')
def help_center():
    return render_template("user/help_center.html")

# =====================================
# ROUTE: CONTACT US
# =====================================
@app.route('/contact-us', methods=['GET', 'POST'])
def contact_us():

    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        message = request.form.get('message')

        # You can store in DB or send email here

    # Email to Admin
        msg = Message(
            subject="New Contact Message - SmartCart",
            sender=app.config['MAIL_USERNAME'],
            recipients=["archanapuli57@gmail.com"]  # 🔥 Put admin email here
        )

        msg.body = f"""New message received from SmartCart:
        Name: {name}
        Email: {email}
        Message: {message}"""

        mail.send(msg)
        flash("Your message has been sent successfully!", "success")
        return redirect('/contact-us')

    return render_template("user/contact_us.html")

# =====================================
# ROUTE: PRIVACY POLICY
# =====================================
@app.route('/privacy-policy')
def privacy_policy():
    return render_template("user/privacy_policy.html")


# ------------------------- RUN APP ------------------------
if __name__ == '__main__':
    app.run(debug=True)
