from flask import Flask, render_template, redirect, session, flash
from flask_debugtoolbar import DebugToolbarExtension
from models import connect_db, db, User, Feedback
from forms import RegisterForm, LoginForm, FeedbackForm
from sqlalchemy.exc import IntegrityError

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql:///feedback"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ECHO"] = True
app.config["SECRET_KEY"] = "abc123"
app.config['DEBUG_TB_INTERCEPT_REDIRECTS'] = False
app.app_context().push()


connect_db(app)
db.create_all()

toolbar = DebugToolbarExtension(app)


@app.route('/')
def register_page():
    """Home page redirects to Register Page"""
    return redirect('/register')


@app.route('/register', methods=['GET', 'POST'])
def register_user():
    """Show Register Form and process the post request of registering a new user and adding to the db"""
    if 'username' in session:
        return redirect(f'/users/{session["username"]}')

    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        email = form.email.data
        first_name = form.first_name.data
        last_name = form.last_name.data
        new_user = User.register(
            username, password, email, first_name, last_name)
        db.session.add(new_user)
        try:
            db.session.commit()
        except IntegrityError:
            form.username.errors.append(
                'Username taken. Please choose another')
            return render_template('users/register.html', form=form)
        session['username'] = new_user.username
        flash('Successfully Created Your Account!', 'success')
        return redirect(f'/users/{new_user.username}')
    return render_template('users/register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login_user():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        user = User.authenticate(username, password)
        if user:
            flash(
                f'Welcome back, {user.full_name}!', 'primary')
            session['username'] = user.username
            return redirect(f'/users/{user.username}')
        else:
            form.username.errors = ['Invalid username/ password!']
    return render_template('users/login.html', form=form)


@app.route('/users/<username>')
def show_user_info(username):
    """Shows the specific logged in user's page"""

    if 'username' not in session or username != session['username']:
        flash(f'Please login as {username} to view account info.', 'danger')
        return redirect('/login')
    user = User.query.filter_by(username=username).first_or_404()
    return render_template('users/details.html', user=user)


@app.route('/logout')
def logout_user():
    session.pop('username')
    flash('You have been successfully logged out', 'info')
    return redirect('/')


@app.route('/users/<username>/delete', methods=['POST'])
def delete_user(username):
    """Delete user and affiliated feedback and redirect to login"""

    if 'username' not in session or username != session['username']:
        flash('You don"t have permission to do that.', 'danger')
        return redirect('/login')
    user = User.query.filter_by(username=username).first_or_404()
    db.session.delete(user)
    db.session.commit()
    session.pop('username')
    flash(f'{username} has been successfully deleted!', 'info')
    return redirect('/login')


@app.route('/users/<username>/feedback/add', methods=['GET', 'POST'])
def show_feedback(username):
    """Show add feedback form and POST feedback"""

    if 'username' not in session or username != session['username']:
        flash(f'Please login as {username} to add feedback', 'danger')
        return redirect('/login')
    user = User.query.filter_by(username=username).first_or_404()
    form = FeedbackForm()
    if form.validate_on_submit():
        title = form.title.data
        content = form.content.data
        new_feedback = Feedback(title=title, content=content, user=user)
        db.session.add(new_feedback)
        db.session.commit()
        flash(
            f'Feedback "{new_feedback.title}" has been successfully added', 'success')
        return redirect(f'/users/{username}')
    return render_template('feedback/add.html', form=form, user=user)


@app.route('/feedback/<int:f_id>/edit', methods=['GET', 'POST'])
def edit_feedback(f_id):
    """Edit feedback and redirect to user page"""
    feedback = Feedback.query.get_or_404(f_id)
    if 'username' not in session or feedback.u_username != session['username']:
        flash(
            f'Please login as {feedback.u_username} to edit or delete feedback', 'danger')
        return redirect('/')

    form = FeedbackForm(obj=feedback)
    if form.validate_on_submit():
        feedback.title = form.title.data
        feedback.content = form.content.data
        db.session.commit()
        flash(
            f'Feedback "{feedback.title}" has been successfully edited', 'success')
        return redirect(f'/users/{feedback.u_username}')
    return render_template('/feedback/edit.html', form=form, feedback=feedback)


@app.route('/feedback/<int:f_id>/delete', methods=['GET', 'POST'])
def delete_feedback(f_id):
    """Delete feedback and redirect to user page"""
    feedback = Feedback.query.get_or_404(f_id)
    if 'username' not in session or feedback.u_username != session['username']:
        flash('You don"t have permission to do that.', 'danger')
        return redirect('/')

    db.session.delete(feedback)
    db.session.commit()
    flash(
        f'Feedback "{feedback.title}" has been successfully deleted', 'success')
    return redirect(f'/users/{feedback.u_username}')
