from flask import Flask, render_template, redirect, url_for, flash, request
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from flask_sqlalchemy import SQLAlchemy
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import InputRequired, Length, Email, EqualTo
from flask_bcrypt import Bcrypt
from flask_wtf.file import FileField, FileAllowed
from werkzeug.utils import secure_filename
import os
from datetime import datetime
from flask_mail import Mail, Message
from flask import jsonify
from functools import wraps


app = Flask(__name__)
app.config['SECRET_KEY'] = '20420171682004'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///autohub.db'  # SQLite database
app.config['UPLOAD_FOLDER'] = 'static/uploads/images'
app.config['ALLOWED_EXTENSIONS'] = {'jpg', 'jpeg', 'png'}  # Add this line

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'retailsysx@gmail.com'
app.config['MAIL_PASSWORD'] = 'qecs yhcc gkeq nlee'
app.config['MAIL_DEFAULT_SENDER'] = 'retailsysx@gmail.com'
# Configuration
app.config['SHOW_LOGIN_PAGE'] = True


db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'user_login'
bcrypt = Bcrypt(app)
# Initialize Flask-Mail
mail = Mail(app)


ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png'}

# Common User class for SQLAlchemy model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    error_log = db.Column(db.Text)

    @property
    def role(self):
        return "admin" if self.is_admin else "user"

    def add_to_error_log(self, error_message):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"{timestamp}: {error_message}\n"
        self.error_log = log_entry + self.error_log if self.error_log else log_entry


# Forms for registration
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=20)])
    email = StringField('Email', validators=[InputRequired(), Email(), Length(max=120)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[InputRequired(), Length(min=8, max=80), EqualTo('password')])
    submit = SubmitField('Register')


# Forms for login
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])
    submit = SubmitField('Login')


# Define the Vehicle model
class Vehicle(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(50))
    make = db.Column(db.String(50))
    model = db.Column(db.String(50))
    first_registration = db.Column(db.String(10))
    mileage = db.Column(db.String(20))
    fuel = db.Column(db.String(20))
    engine_size = db.Column(db.String(20))
    power = db.Column(db.String(20))
    gearbox = db.Column(db.String(20))
    num_seats = db.Column(db.String(5))
    doors = db.Column(db.String(5))
    color = db.Column(db.String(20))
    is_featured = db.Column(db.Boolean, default=False)

    # Establishing a relationship with the AdditionalDetails model
    additional_details = db.relationship('AdditionalDetails', backref='vehicle', uselist=False)


class AdditionalDetails(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    price = db.Column(db.String(20))
    description = db.Column(db.Text)
    extras = db.Column(db.Text)
    images = db.Column(db.String(255))  # Store image filenames as a comma-separated string
    vehicle_id = db.Column(db.Integer, db.ForeignKey('vehicle.id'))


# Form for adding a new vehicle
class AddVehicleForm(FlaskForm):
    type = StringField('Type', validators=[InputRequired()])
    make = StringField('Make', validators=[InputRequired()])
    model = StringField('Model', validators=[InputRequired()])
    first_registration = StringField('First Registration', validators=[InputRequired()])
    mileage = StringField('Mileage', validators=[InputRequired()])
    fuel = StringField('Fuel', validators=[InputRequired()])
    engine_size = StringField('Engine Size', validators=[InputRequired()])
    power = StringField('Power', validators=[InputRequired()])
    gearbox = StringField('Gearbox', validators=[InputRequired()])
    num_seats = StringField('Number of Seats', validators=[InputRequired()])
    doors = StringField('Doors', validators=[InputRequired()])
    color = StringField('Color', validators=[InputRequired()])
    price = StringField('Price', validators=[InputRequired()])
    description = TextAreaField('Description', validators=[InputRequired()])
    extras = TextAreaField('Extras', validators=[InputRequired()])
    images = FileField('Images', validators=[FileAllowed(app.config['ALLOWED_EXTENSIONS'], 'Images only!')])


class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    subject = db.Column(db.String(255), nullable=False)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    replied = db.Column(db.Boolean, default=False)

    @classmethod
    def get_all_messages(cls):
        return cls.query.all()

    def __repr__(self):
        return f'<Contact {self.name}>'


class ContactForm(FlaskForm):
    name = StringField('Name', validators=[InputRequired()])
    email = StringField('Email', validators=[InputRequired(), Email()])
    subject = StringField('Subject', validators=[InputRequired()])
    message = TextAreaField('Message', validators=[InputRequired()])
    submit = SubmitField('Send Message')


class Blog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    author = db.Column(db.String(50), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    image_url = db.Column(db.String(200), nullable=True)

    def __repr__(self):
        return f"Blog(id={self.id}, title={self.title}, author={self.author})"


# Route for user registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('user_login'))

    return render_template('register.html', form=form)


# Route for the home page
@app.route('/')
def home():
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for('admin_dashboard'))

    cars = Vehicle.query.all()  # Fetch all cars from the database

    if app.config['SHOW_LOGIN_PAGE']:
        return render_template('pages/index.html', cars=cars)
    else:
        return render_template('pages/maintenance.html', cars=cars)

def maintenance_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not app.config['SHOW_LOGIN_PAGE']:
            return render_template('pages/maintenance.html')
        return f(*args, **kwargs)
    return decorated_function

@app.route('/toggle_switch', methods=['POST'])
def toggle_switch():
    app.config['SHOW_LOGIN_PAGE'] = not app.config['SHOW_LOGIN_PAGE']
    return redirect('/admin/dashboard')


# Route for user login
@app.route('/user/login', methods=['GET', 'POST'])
def user_login():
    form = LoginForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        # Check if a user with the given username and password exists
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash(f'Login successful! Welcome, {user.username} ({user.role})', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password', 'danger')

    return render_template('user_login.html', form=form)


# ... (previous code)

# Forms for registration
class AdminRegistrationForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=20)])
    email = StringField('Email', validators=[InputRequired(), Email(), Length(max=120)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[InputRequired(), Length(min=8, max=80), EqualTo('password')])
    submit = SubmitField('Register')


# Route for admin registration
@app.route('/admin/register', methods=['GET', 'POST'])
def admin_register():
    form = AdminRegistrationForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        admin = User(username=form.username.data, email=form.email.data, password=hashed_password, is_admin=True)
        db.session.add(admin)
        db.session.commit()
        flash('Admin registration successful! You can now log in as an admin.', 'success')
        return redirect(url_for('admin_login'))

    return render_template('admin_register.html', form=form)


@login_manager.user_loader
def load_user(user_id):
    # Check the User table
    user = User.query.get(int(user_id))
    if user:
        return user

    return None


# Route for admin login
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    form = LoginForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        # Check if an admin with the given username and password exists
        admin = User.query.filter_by(username=username, is_admin=True).first()

        if admin and bcrypt.check_password_hash(admin.password, password):
            login_user(admin)
            flash(f'Login successful! Welcome, {admin.username} (Admin)', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password', 'danger')

    return render_template('admin_login.html', form=form)


# Update the admin_dashboard route in app.py
@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    # Fetch all users
    users = User.query.all()

    # Query all cars from the database
    all_cars = Vehicle.query.all()

    # Count the number of cars for each make and model
    make_counts = {}
    make_models = {}

    for car in all_cars:
        make = car.make
        model = car.model

        # Increment make count
        make_counts[make] = make_counts.get(make, 0) + 1

        # Increment model count within make
        if make not in make_models:
            make_models[make] = {}

        make_models[make][model] = make_models[make].get(model, 0) + 1

    # Fetch key application statistics
    total_users = User.query.count()
    total_vehicles = len(all_cars)

    # Fetch all contact messages from the database
    messages = Contact.get_all_messages()

    return render_template('admin_dashboard.html', make_counts=make_counts, make_models=make_models, users=users,
                           total_users=total_users, total_vehicles=total_vehicles, error_log=current_user.error_log,
                           messages=messages)


@app.route('/user/main')
@login_required
def user_main():
    return render_template('user_main.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logout successful!', 'success')
    return redirect(url_for('home'))


@app.route('/car_details/<int:car_id>')
@maintenance_required
def car_details(car_id):
    car = Vehicle.query.get_or_404(car_id)
    return render_template('pages/car-details.html', car=car)


# Route to display the form for adding a new vehicle
@app.route('/add_vehicle_form', methods=['GET', 'POST'])
@maintenance_required
def add_vehicle_form():
    form = AddVehicleForm()

    if form.validate_on_submit():
        # Process the form data as needed

        flash('Vehicle added successfully!')
        return redirect(url_for('home'))

    return render_template('admin/add_vehicle.html', form=form)


# Route for adding a new vehicle
@app.route('/add_vehicle', methods=['GET', 'POST'])
@maintenance_required
def add_vehicle():
    if request.method == 'POST':
        # Extract existing vehicle details
        type = request.form['type']
        make = request.form['make']
        model = request.form['model']
        first_registration = request.form['first_registration']
        mileage = request.form['mileage']
        fuel = request.form['fuel']
        engine_size = request.form['engine_size']
        power = request.form['power']
        gearbox = request.form['gearbox']
        num_seats = request.form['num_seats']
        doors = request.form['doors']
        color = request.form['color']

        # Extract additional details
        price = request.form['price']
        description = request.form['description']
        extras = request.form['extras']

        # Handle image uploads
        if 'images' in request.files:
            images = request.files.getlist('images')  # Use getlist to retrieve multiple files
            image_filenames = save_images(images)
        else:
            image_filenames = []

        # Create Vehicle instance (moved outside of the else block)
        vehicle = Vehicle(
            type=type,
            make=make,
            model=model,
            first_registration=first_registration,
            mileage=mileage,
            fuel=fuel,
            engine_size=engine_size,
            power=power,
            gearbox=gearbox,
            num_seats=num_seats,
            doors=doors,
            color=color
        )

        # Create AdditionalDetails instance
        additional_details = AdditionalDetails(
            price=price,
            description=description,
            extras=extras,
            images=','.join(image_filenames)
        )

        # Associate the AdditionalDetails with the Vehicle
        vehicle.additional_details = additional_details

        # Save to the database
        db.session.add(vehicle)
        db.session.commit()

        flash('Vehicle added successfully!')
        return redirect(url_for('home'))

    return render_template('admin/add_vehicle.html')


# Helper function to save a single image
def save_image(image):
    filename = secure_filename(image.filename)
    image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    return filename


# Helper function to save multiple images
def save_images(images):
    filenames = []
    for image in images:
        filename = save_image(image)
        filenames.append(filename)
    return filenames


@app.route('/admin/view_and_delete_cars', methods=['GET', 'POST'])
@maintenance_required
@login_required
def view_and_delete_cars():
    # Check if the current user is an admin
    if not current_user.is_admin:
        flash('Permission denied. Only admin users can view and delete cars.', 'danger')
        return redirect(url_for('home'))

    # Fetch all cars from the database
    cars = Vehicle.query.all()

    if request.method == 'POST':
        car_id = request.form.get('feature_car_id')
        if car_id:
            car = Vehicle.query.get(car_id)
            if car:
                car.is_featured = not car.is_featured  # Toggle the state
                db.session.commit()

    return render_template('admin/view_and_delete_cars.html', cars=cars)


@app.route('/delete_vehicle/<int:car_id>', methods=['POST'])
@maintenance_required
@login_required
def delete_vehicle(car_id):
    # Check if the current user is an admin
    if not current_user.is_admin:
        flash('Permission denied. Only admin users can delete vehicles.', 'danger')
        return redirect(url_for('home'))

    # Fetch the vehicle from the database
    vehicle = Vehicle.query.get_or_404(car_id)

    # Delete the vehicle and associated details from the database
    db.session.delete(vehicle)
    db.session.commit()

    flash('Vehicle deleted successfully!', 'success')
    return redirect(url_for('view_and_delete_cars'))


# Route to edit a specific vehicle
@app.route('/edit_vehicle/<int:id>', methods=['GET', 'POST'])
@maintenance_required
def edit_vehicle(id):
    vehicle = Vehicle.query.get_or_404(id)

    if request.method == 'POST':
        # Update Vehicle model attributes
        vehicle.type = request.form['type']
        vehicle.make = request.form['make']
        vehicle.model = request.form['model']
        vehicle.first_registration = request.form['first_registration']
        vehicle.mileage = request.form['mileage']
        vehicle.fuel = request.form['fuel']
        vehicle.engine_size = request.form['engine_size']
        vehicle.power = request.form['power']
        vehicle.gearbox = request.form['gearbox']
        vehicle.num_seats = request.form['num_seats']
        vehicle.doors = request.form['doors']
        vehicle.color = request.form['color']

        # Update AdditionalDetails model attributes
        additional_details = vehicle.additional_details
        additional_details.price = request.form['price']
        additional_details.description = request.form['description']
        additional_details.extras = request.form['extras']
        additional_details.images = request.form['images']

        db.session.commit()
        return redirect(url_for('view_vehicle', id=vehicle.id))

    return render_template('admin/edit_vehicle.html', vehicle=vehicle)


# Route to view a specific vehicle
@app.route('/view_vehicle/<int:id>')
@maintenance_required
def view_vehicle(id):
    vehicle = Vehicle.query.get_or_404(id)
    return render_template('admin/view_vehicle.html', vehicle=vehicle)


@app.route('/all_cars', methods=['GET'])
@maintenance_required
def all_cars():
    # Query distinct values for each filter field
    vehicle_types = Vehicle.query.with_entities(Vehicle.type).distinct().all()
    makes = Vehicle.query.with_entities(Vehicle.make).distinct().all()
    fuels = Vehicle.query.with_entities(Vehicle.fuel).distinct().all()
    gearboxes = Vehicle.query.with_entities(Vehicle.gearbox).distinct().all()

    # Convert the results to flat lists
    vehicle_types = [type_[0] for type_ in vehicle_types]
    makes = [make[0] for make in makes]
    fuels = [fuel[0] for fuel in fuels]
    gearboxes = [gearbox[0] for gearbox in gearboxes]

    # Get filter values from request parameters
    type_filter = request.args.get('type')
    make_filter = request.args.get('make')
    fuel_filter = request.args.get('fuel')
    gearbox_filter = request.args.get('gearbox')

    # Construct the base query
    query = Vehicle.query

    # Apply filters if they are present
    if type_filter:
        query = query.filter(Vehicle.type == type_filter)
    if make_filter:
        query = query.filter(Vehicle.make == make_filter)
    if fuel_filter:
        query = query.filter(Vehicle.fuel == fuel_filter)
    if gearbox_filter:
        query = query.filter(Vehicle.gearbox == gearbox_filter)

    # Execute the query
    filtered_cars = query.all()

    # Get all cars
    all_cars = Vehicle.query.all()

    # Determine applied filters
    applied_filters = []

    if type_filter:
        applied_filters.append(f'Type: {type_filter}')
    if make_filter:
        applied_filters.append(f'Make: {make_filter}')
    if fuel_filter:
        applied_filters.append(f'Fuel: {fuel_filter}')
    if gearbox_filter:
        applied_filters.append(f'Gearbox: {gearbox_filter}')

    filters_applied = ', '.join(applied_filters)

    # Debugging: Print the value of filters_applied
    print("Filters Applied:", filters_applied)

    # Pass the distinct values, filtered cars, and filters_applied to the template
    return render_template('pages/cars.html', vehicle_types=vehicle_types, makes=makes, fuels=fuels,
                           gearboxes=gearboxes,
                           cars=filtered_cars, all_cars=all_cars, filters_applied=filters_applied)


@app.route('/about')
@maintenance_required
def about():
    return render_template('pages/about.html')


@app.route('/team')
@maintenance_required
def team():
    return render_template('pages/team.html')


@app.route('/blog')
@maintenance_required
def blog():
    # Fetch all blogs from the database
    blogs = Blog.query.all()

    return render_template('pages/blog.html', blogs=blogs)


@app.route('/view_blog/<int:blog_id>')
@maintenance_required
def view_blog(blog_id):
    # Fetch the specific blog from the database
    blog = Blog.query.get_or_404(blog_id)

    return render_template('pages/blog-post.html', blog=blog)


@app.route('/testimonials')
@maintenance_required
def testimonials():
    return render_template('pages/testimonials.html')


@app.route('/faq')
@maintenance_required
def faq():
    return render_template('pages/faq.html')


@app.route('/terms')
@maintenance_required
def terms():
    return render_template('pages/terms.html')


@app.route('/contact')
@maintenance_required
def contact():
    return render_template('pages/contact.html')


# Add a new route to handle user deletion
@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
@maintenance_required
def delete_user(user_id):
    # Ensure that the logged-in user is an admin (optional)
    if not current_user.is_admin:
        flash('Permission denied. Only admin users can delete users.', 'danger')
        return redirect(url_for('admin_dashboard'))

    # Fetch the user from the database
    user = User.query.get_or_404(user_id)

    # Delete the user from the database
    db.session.delete(user)
    db.session.commit()

    flash('User deleted successfully!', 'success')
    return redirect(url_for('admin_dashboard'))

'''
@app.errorhandler(Exception)
def error_handler(e):
    # Log the error
    current_user.add_to_error_log(str(e))

    # You may also log additional details like stack trace
    import traceback
    error_traceback = traceback.format_exc()
    current_user.add_to_error_log(error_traceback)

    # Render an error page or redirect to a specific error route
    return render_template('admin/error.html', error_message=str(e)), 500
'''

@app.route('/', methods=['GET', 'POST'])
def submit_form():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        subject = request.form.get('subject')
        message = request.form.get('message')

        # Create a new Contact instance and add it to the database
        new_contact = Contact(name=name, email=email, subject=subject, message=message)
        db.session.add(new_contact)
        db.session.commit()

        return "Form submitted successfully!"

    return render_template('admin_dashboard.html')  # Replace with the actual name of your HTML template


@app.route('/reply/<int:contact_id>', methods=['GET', 'POST'])
def reply_form(contact_id):
    contact = Contact.query.get_or_404(contact_id)

    if request.method == 'POST':
        reply_message = request.form.get('reply_message')

        # Send the reply as an email
        send_reply_email(contact.email, contact.name, reply_message)

        # Update the replied status
        contact.replied = True
        db.session.commit()

        # Redirect to the admin dashboard route
        return redirect(url_for('admin_dashboard'))

    return render_template('admin/reply_form.html', contact=contact)


def send_reply_email(receiver_email, receiver_name, reply_message):
    # This function sends the reply as an email
    subject = 'Your Message Reply'
    body = f"Dear {receiver_name},\n\nThank you for your message. Here is the reply:\n\n{reply_message}\n\nBest regards,\nAutoHub Team\na subsidiary of RetailSysX"

    # Create a Message instance
    message = Message(subject=subject, recipients=[receiver_email], body=body)

    # Send the email
    mail.send(message)




@app.route('/delete/<int:contact_id>', methods=['POST'])
def delete_message(contact_id):
    contact = Contact.query.get_or_404(contact_id)

    # Delete the contact message from the database
    db.session.delete(contact)
    db.session.commit()

    return redirect(url_for('admin_dashboard'))


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/add_blog', methods=['GET', 'POST'])
@maintenance_required
def add_blog():
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        author = request.form.get('author')

        # Check if the post request has the file part
        if 'image' not in request.files:
            flash('No file part')
            return redirect(request.url)

        file = request.files['image']

        # If the user does not select a file, the browser submits an empty file without a filename
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)

        # Check if the file extension is allowed
        if file and allowed_file(file.filename):
            # Secure the filename to prevent any malicious activity
            filename = secure_filename(file.filename)

            # Save the file to the upload folder
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

            image_url = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        else:
            flash('Invalid file format. Allowed formats are jpg, jpeg, and png.')
            return redirect(request.url)

        new_blog = Blog(title=title, content=content, author=author, image_url=image_url)
        db.session.add(new_blog)
        db.session.commit()

        flash('Blog added successfully!')
        return redirect(url_for('blog'))

    return render_template('admin/add_blog.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create tables before running the app
    app.run(debug=True)
