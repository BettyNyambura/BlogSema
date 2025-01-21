from flask import render_template, redirect, url_for, request, flash
from app import db, mail, bcrypt
from app.models import User, Blog
import re
from flask_login import login_user, current_user, login_required, logout_user
from flask_mail import Message

# Function to validate password
def validate_password(password):
    errors = []
    
    if len(password) < 6:
        errors.append("Your Password must be at least 6 characters long.")
    if not re.search(r'[A-Z]', password):
        errors.append("Your Password must contain at least 1 uppercase letter.")
    if not re.search(r'[a-z]', password):
        errors.append("Your Password must contain at least 1 lowercase letter.")
    if not re.search(r'\d', password):
        errors.append("Your Password must contain at least 1 number.")
    if not re.search(r'[@$!%*?&]', password):
        errors.append("Your Password must contain at least 1 special character (e.g., @$!%*?&).")
    
    return errors
    
def init_routes(app):
    @app.route('/', methods=['GET', 'POST'])
    def home():
        return render_template('home.html')

    # Route to Login
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            email = request.form['email']
            password = request.form['password']
        
            # Check if user exists and the password matches
            user = User.query.filter_by(email=email).first()
        
            if user and bcrypt.check_password_hash(user.password, password):
                # Log the user in
                login_user(user)

                # Get the 'next' parameter from the query string
                next_url = request.args.get('next')

                # Redirect the user to the blog creation page
                return redirect(next_url or url_for('home'))

            flash('Login Unsuccessful. Please check your email and password.', 'danger')
            return redirect(url_for('login'))

        return render_template('login.html', exclude_navbar=False)

    # Route to sign-up
    @app.route('/signup', methods=['GET', 'POST'])
    def signup():
        if request.method == 'POST':
            username = request.form['username']
            email = request.form['email']
            password = request.form['password']
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

            # Checking if password meets the requirements
            password_errors = validate_password(password)
            # loop to flash each error message
            if password_errors:
                for error in password_errors:
                    flash(error, 'danger')
                return redirect(url_for('signup'))

            # Checking if user exists
            existing_user = User.query.filter_by(email=email).first()
            if existing_user:
                flash('Email address already registered. You can log in', 'danger')
                return redirect(url_for('signup'))

            # Create new user
            new_user = User(username=username, email=email, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()

            flash('Your account has been created successfully! <a href="' + url_for('login') + '">Log in here</a>.', 'success')
            return redirect(url_for('login'))

        return render_template('signup.html')

    # Route to create blogs and requires log in
    @app.route('/create-blog', methods=['GET', 'POST'])
    @login_required
    def create_blog():
        if request.method == 'POST':
            title = request.form['title']
            content = request.form['content']
            tags = request.form['tags']

            # Create a new blog post
            new_blog = Blog(title=title, content=content, tags=tags, user_id=current_user.id)
            db.session.add(new_blog)
            db.session.commit()

            return redirect(url_for('view_blogs'))  # Redirect to a page where blogs are listed

        next_url = request.args.get('next')
        return render_template('create_blog.html')
    
    # Submitting blog
    @app.route('/submit_blog', methods=['GET', 'POST'])
    def submit_blog():
        if request.method == 'POST':
            title = request.form.get('title')
            content = request.form.get('content')
            tags = request.form.get('tags')

            # Ensuring title and content are present
            if not title or not content:
                flash('Title and content are required!', 'error')
                return redirect(url_for('create_blog'))  # Or wherever you want to redirect if validation fails

            if current_user.is_authenticated:
                user_id = current_user.id

                # Create a new blog post
                new_blog = Blog(title=title, content=content, tags=tags, user_id=user_id)
                
                try:
                    db.session.add(new_blog)
                    db.session.commit()

                    # flash('Bogy Blogy Blogy!', 'success')

                    return render_template('submit_blog.html', title=title)  # Redirect to the home page

                except Exception as e:
                    db.session.rollback()  # **Rollback in case of an error**
                    flash(f'Error: {e}', 'danger')

            else:
                flash('Please log in to create a blog.', 'danger')

        return render_template('submit_blog.html')
    
    # Redirecting to viewing blog 
    @app.route('/my-blogs')
    @login_required
    def view_blogs():
        blogs = Blog.query.all()
        return render_template('view_blogs.html', blogs=blogs, page_class="blog-page")
    
    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        return redirect(url_for('home'))  # Redirect to home page after logout

    @app.route('/delete-blog/<int:blog_id>', methods=['POST'])
    @login_required
    def delete_blog(blog_id):
        blog = Blog.query.get_or_404(blog_id)

        # Check if the blog belongs to the current user
        if blog.user_id != current_user.id:
            flash('You do not have permission to delete this blog.', 'danger')
            return redirect(url_for('view_blogs'))

        # Delete the blog
        db.session.delete(blog)
        db.session.commit()
        flash('Blog deleted successfully.', 'success')
        return redirect(url_for('view_blogs'))
        
    @app.route('/forgot-password', methods=['GET', 'POST'])
    def forgot_password():
        if request.method == 'POST':
            email = request.form['email']
            user = User.query.filter_by(email=email).first()  # Find user by email
            if user:
                # Generate reset token (you can use any method of token generation, such as itsdangerous or UUID)
                token = generate_reset_token(user)  # Implement this function
                    
                reset_url = url_for('reset_password', token=token, _external=True)
                send_reset_email(user, reset_url)  # Implement this function to send the reset email
                    
                flash('An email with a password reset link has been sent!', 'info')
            return redirect(url_for('login'))
                
            flash('No user found with that email address.', 'danger')
        return render_template('forgot_password.html')

def send_reset_email(user, reset_url):
    msg = Message('Password Reset Request',
                  sender='noreply@yourapp.com',
                  recipients=[user.email])
    msg.body = f"To reset your password, visit the following link: {reset_url}"
    mail.send(msg)