from flask import Flask, render_template, redirect, url_for, abort, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from flask_bootstrap import Bootstrap
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from sqlalchemy.orm import relationship
from wtforms import StringField, SubmitField, SelectField, PasswordField
from wtforms.validators import DataRequired, URL
from sqlalchemy.sql.expression import func
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os

app = Flask(__name__)

Bootstrap(app)
app.secret_key = os.environ.get("SECRET_KEY")
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///Cafe and Wifi Website.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)


# FORMS
class AddForm(FlaskForm):
    name = StringField('Cafe Name', validators=[DataRequired()])
    map_url = StringField('Cafe Location on Google Maps (URL)', validators=[URL()])
    img_url = StringField("Image of the interior", validators=[URL()])
    location = StringField("Location Area", validators=[DataRequired()])
    seats = StringField("Number of seats", validators=[DataRequired()])
    has_toilet = SelectField("Bathroom", choices=[("✔"), ("✖")], validators=[DataRequired()])
    has_wifi = SelectField("WiFi", choices=[("✔"), ("✖")], validators=[DataRequired()])
    has_sockets = SelectField("Sockets", choices=[("✔"), ("✖")], validators=[DataRequired()])
    coffee_price = StringField("Coffee Price", validators=[DataRequired()])
    submit = SubmitField('Submit')


class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    name = StringField("Name", validators=[DataRequired()])
    submit = SubmitField("Sign Me Up!")


class LogInForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Let Me In!")


# TABLES
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), nullable=False, unique=True)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False)
    user_cafes = relationship("Cafe", back_populates="cafe_author")


class Cafe(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    cafe_author = relationship("User", back_populates="user_cafes")
    name = db.Column(db.String(250), unique=True, nullable=False)
    map_url = db.Column(db.String(500), nullable=False)
    img_url = db.Column(db.String(500), nullable=False)
    location = db.Column(db.String(250), nullable=False)
    seats = db.Column(db.String(250), nullable=False)
    has_toilet = db.Column(db.Boolean, nullable=False)
    has_wifi = db.Column(db.Boolean, nullable=False)
    has_sockets = db.Column(db.Boolean, nullable=False)
    coffee_price = db.Column(db.String(250), nullable=True)


db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def admin_only(function):
    @wraps(function)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated and current_user.id == 1:
            return function(*args, **kwargs)
        else:
            abort(403)
    return decorated_function


# ROUTES
@app.route("/")
def home():
    return render_template("index.html")


@app.route('/register', methods=["GET", "POST"])
def register():
    register_form = RegisterForm()
    if register_form.validate_on_submit():
        if User.query.filter_by(email=register_form.email.data).first():
            flash("You've already signed up with this email. Log In instead!")
            return redirect(url_for('login'))
        else:
            hash_password = generate_password_hash(
                password=register_form.password.data,
                method="pbkdf2:sha256",
                salt_length=8
            )
            new_user = User(
                email=register_form.email.data,
                password=hash_password,
                name=register_form.name.data
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for("show_cafes"))
    return render_template("register.html", form=register_form)


@app.route('/login', methods=["GET", "POST"])
def login():
    login_form = LogInForm()
    if login_form.validate_on_submit():
        user = User.query.filter_by(email=login_form.email.data).first()
        if user:
            if check_password_hash(user.password, login_form.password.data):
                login_user(user)
                return redirect(url_for("show_cafes"))
            else:
                flash("Password incorrect, please try again.")
                return redirect(url_for('login'))
        else:
            flash("That email does not exist. Please try again!")
            return redirect(url_for('login'))
    return render_template("login.html", form=login_form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route("/cafes")
def show_cafes():
    all_cafes = db.session.query(Cafe).all()
    is_cafe = True
    if not all_cafes:
        is_cafe = False
    return render_template("cafes.html", cafes=all_cafes, is_cafe=is_cafe)


@app.route("/details/<int:cafe_id>")
def show_details(cafe_id):
    requested_cafe = Cafe.query.get(cafe_id)
    return render_template("cafe-details.html", cafe=requested_cafe)


@app.route("/random")
def random():
    random_cafe = Cafe.query.order_by(func.random()).first()
    return redirect(url_for('show_details', cafe_id=random_cafe.id))


@app.route("/add", methods=["GET", "POST"])
@login_required
def add_cafe():
    add_form = AddForm()
    if add_form.validate_on_submit():
        if add_form.has_toilet.data == "✖":
            add_form.has_toilet.data = False
        if add_form.has_wifi.data == "✖":
            add_form.has_wifi.data = False
        if add_form.has_sockets.data == "✖":
            add_form.has_sockets.data = False
        new_cafe = Cafe(
            author_id=current_user.id,
            name=add_form.name.data,
            map_url=add_form.map_url.data,
            img_url=add_form.img_url.data,
            location=add_form.location.data,
            seats=add_form.seats.data,
            coffee_price=add_form.coffee_price.data,
            has_toilet=bool(add_form.has_toilet.data),
            has_wifi=bool(add_form.has_wifi.data),
            has_sockets=bool(add_form.has_sockets.data),
        )
        db.session.add(new_cafe)
        db.session.commit()
        return redirect(url_for('show_cafes'))
    return render_template("add.html", form=add_form)


@app.route("/delete/<cafe_id>", methods=["DELETE", "GET"])
@admin_only
def delete_cafe(cafe_id):
    cafe_to_delete = Cafe.query.get(cafe_id)
    db.session.delete(cafe_to_delete)
    db.session.commit()
    return redirect(url_for('show_cafes'))


if __name__ == '__main__':
    app.run(debug=True)
