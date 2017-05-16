

from flask import Flask
from flask import render_template,redirect,url_for,request,flash
app = Flask(__name__)


from flask_bootstrap import Bootstrap
bootstrap = Bootstrap(app)


from flask_login import login_user


from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField,BooleanField,SubmitField
from wtforms.validators import Required,Length,Email,Regexp,EqualTo

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[Required(), Length(1,64),Email()])
    password = PasswordField('Password', validators=[Required()])
    remember_me = BooleanField('Keep me logged in')
    submit = SubmitField('Log In')


import os
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
basedir = os.path.abspath(os.path.dirname(__file__))
db = SQLAlchemy(app)


@app.route('/')
def hello_world():
    return render_template('index.html')


@app.route('/', methods = ['GET','POST'])
def login():
    form = LoginForm()

    return render_template('auth/login.html')


class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer,primary_key=True)
    name = db.Column(db.String(64),unique=True)
    users = db.relationship('user',backref='role',lazy='dynamic')

    def __repr__(self):
        return '<Role %r>' % self.name


class User(UserMixin,db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(64),unique=True,index=True)
    username = db.Column(db.String(64), unique=True,index=True)
    role_id = db.Column(db.Integer,db.ForeignKey('roles.id'))
    password_hash = db.Column(db.String(128))
    confirmed = db.Column(db.Boolean,default=False)

    def __repr__(self):
        return '<User %r>' % self.username





if __name__ == '__main__':
    app.run()
