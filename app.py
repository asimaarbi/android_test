import threading
import requests
import json

from flask import Flask, redirect, render_template, request, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

from flask_admin.contrib.sqla import ModelView
import flask_admin as admin
from flask_admin import expose
from flask_admin.base import AdminIndexView
from flask_admin.menu import MenuLink

from flask_restful import Resource, Api, reqparse
from flask_marshmallow import Marshmallow

KEY_FIREBASE_SERVER = "AAAA_CIfhwU:APA91bFlC5oIXTT8VVMqcb1_Q0ZPhFCDUFgi_TzvLEzNAKp" \
                      "nLzbtXw6x2LYOJyVYLVUPmcNL1Vv-6D3joXM09J-jv2HGLwrik6Z3F4oBGdp" \
                      "WEcZSeae88NjRArZdhbdqpGCC5WpJnx-z"
HEADER = {
    'Authorization': 'key={}'.format(KEY_FIREBASE_SERVER),
    'Content-Type': 'application/json'
}
URL_FCM = 'https://fcm.googleapis.com/fcm/send'

app = Flask(__name__)
app.config['SECRET_KEY'] = '5791628bb0b13ce0c676dfde280ba245'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///main.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
api = Api(app)
db = SQLAlchemy(app)
ma = Marshmallow(app)

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'nikedtechstartup@gmail.com'
app.config['MAIL_PASSWORD'] = 'startupnik51'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True


# mail = Mail(app)


@app.route('/message')
def messege():
    return render_template('message.html')


@app.route('/send', methods=['POST'])
def send():
    title = request.form['username']
    message = request.form['password']
    _send_push(title, message)
    flash("Message Sent")
    return render_template('message.html')


def _send_push(title, message):
    data = {"data": {"title": f'{title}', "message": f'{message}'},
            "to": "/topics/all_users"}
    requests.post(URL_FCM, data=json.dumps(data), headers=HEADER)


def send_push():
    thread = threading.Thread(target=_send_push)
    thread.start()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=True)
    firstname = db.Column(db.String(50), nullable=True)
    lastname = db.Column(db.String(50), nullable=True)
    email = db.Column(db.String(50), nullable=True)
    password = db.Column(db.String(255), nullable=True)
    mobile = db.Column(db.String(50), nullable=True)

    def __str__(self):
        return self.name


class UserSchema(ma.SQLAlchemyAutoSchema):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, exclude=('password',), **kwargs)

    class Meta:
        model = User


class NamesResource(Resource):
    def get(self):
        names = ['mahad', 'muzammil', 'hamza', 'husnain',
                 'shahid', 'bilal', 'asim', 'omer']
        return names, 200


class UserResource(Resource):
    def post(self):
        parser = reqparse.RequestParser(bundle_errors=True)
        parser.add_argument('username', type=str, help='username of the User', required=True)
        parser.add_argument('firstname', type=str, help='Fisrt name of the User', required=True)
        parser.add_argument('lastname', type=str, help='Last name of the User', required=True)
        parser.add_argument('email', type=str, help='Email of the User', required=True)
        parser.add_argument('password', type=str, help='Password of the User', required=True)
        parser.add_argument('mobile', type=str, help='Mobile # of the User', required=False)
        args = parser.parse_args(strict=True)
        args['password'] = generate_password_hash(args['password'])
        email = args['email']
        user = User.query.filter_by(email=email).first()
        if user:
            return {'message': 'Email Already Exist'}, 400

        custom_args = {}
        for k, v in args.items():
            if v:
                custom_args.update({k: v})

        user = User(**custom_args)

        db.session.add(user)
        db.session.commit()

        schema = UserSchema()
        return schema.jsonify(user)

    def put(self):
        parser = reqparse.RequestParser(bundle_errors=True)
        parser.add_argument('username', type=str, help='username of the User', required=False)
        parser.add_argument('firstname', type=str, help='Fisrt name of the User', required=False)
        parser.add_argument('lastname', type=str, help='Last name of the User', required=False)
        parser.add_argument('email', type=str, help='Email of the User', required=True)
        parser.add_argument('password', type=str, help='Password of the User', required=False)
        parser.add_argument('mobile', type=str, help='Mobile # of the User', required=False)
        args = parser.parse_args(strict=True)
        email = args['email']
        user = User.query.filter_by(email=email).first()
        if not user:
            return "user not exit", 404

        for k, v in args.items():
            if v:
                setattr(user, k, v)
        db.session.commit()

        schema = UserSchema()
        return schema.jsonify(user)

    def get(self):
        schema = UserSchema(many=True)
        return schema.dump(User.query.all())


class SendPush(Resource):
    def post(self):
        send_push()
        return "OK"


class Applogin(Resource):
    def post(self):
        parser = reqparse.RequestParser(bundle_errors=True)
        parser.add_argument('email', type=str, help='Email', required=True)
        parser.add_argument('password', type=str, help='Password', required=True)
        args = parser.parse_args(strict=True)
        email = args['email']
        password = args['password']
        if email == 'admin' and password == 'password':
            return {'message': f'{email} Logged IN'}
        user = User.query.filter_by(email=email).first()
        if not user:
            return "User not exists", 400
        if user:
            if check_password_hash(user.password, password):
                schema = UserSchema()
                return schema.jsonify(user)
            return "Invalid Password or Name", 400


class GetUser(Resource):
    def get(self, email):
        user = User.query.filter_by(email=email).first()
        if not user:
            return {'message': 'User not found'}, 404

        if not user.enabled:
            return {'message': 'Not allowed to login'}, 403

        schema = UserSchema()
        return schema.jsonify(user)


def load_user(session):
    if session['logged_in'] == session:
        return True


@app.route('/login', methods=['POST'])
def login():
    if request.form['username'] == 'admin' and request.form['password'] == 'password':
        session['logged_in'] = True
        return redirect('/user')


@app.route('/logout')
def logout():
    session['logged_in'] = False
    return render_template('login.html')


class MyAdminIndexView(AdminIndexView):
    @expose('/')
    def index(self):
        if not session.get('logged_in'):
            return render_template('login.html')
        return super().index()


class UserModelView(ModelView):
    can_edit = False
    can_create = False
    column_list = ['username', 'firstname', 'lastname', 'email', ]

    def is_accessible(self):
        if session.get('logged_out'):
            return False
        if session.get('logged_in'):
            return True


admin = admin.Admin(app, name='Admin', index_view=MyAdminIndexView(name=' '), url='/admin')
admin.add_view(UserModelView(User, db.session, url='/user'))
admin.add_link(MenuLink(name='Logout', category='', url="/logout"))
admin.add_link(MenuLink(name='Send Message', category='', url="/message"))
api.add_resource(NamesResource, '/api/names/')
api.add_resource(UserResource, '/api/users/')
api.add_resource(Applogin, '/api/login/')

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
