from asyncio.windows_events import NULL
from email.policy import default
from enum import unique
from importlib import resources
from importlib.metadata import metadata
from os import stat
from select import select
from tkinter.messagebox import QUESTION
from turtle import update
from xmlrpc.client import Boolean
from flask import Flask, jsonify, make_response, request, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
import uuid
import jwt
import datetime
from flask_cors import CORS, cross_origin
from sqlalchemy import ForeignKey, Integer, Table, Column, MetaData, Boolean, create_engine, String, insert, null, select, true, update, insert


app = Flask(__name__)
cors = CORS(app)

# class Gender(Enum):
#     MALE="Male"
#     FEMALE="Female"
#     NON="None of them"

app.config['SECRET_KEY'] = 'thisissecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///stunder_database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True


db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    email = db.Column(db.String(50))
    password = db.Column(db.String(80))
    gender = db.Column(db.String(20))
    description = db.Column(db.String(150))
    admin = db.Column(db.Boolean)


class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(50), ForeignKey('subject.text'), nullable=False)
    asker = db.Column(db.String(50), default='')
    helper = db.Column(db.String(50), default='')
    status = db.Column(db.Boolean, default=False)


class Subject(db.Model):
    id = db.Column(db.Integer, primary_key=True,)
    text = db.Column(db.String(50), unique=True, nullable=False)


def create_question_model(tablename):
    engine = create_engine('sqlite:///stunder_second.db', echo=True)
    meta = MetaData()

    table = Table(
        tablename, meta,
        Column('id', Integer, primary_key=True),
        Column('user_name', String, unique=True),
        Column('ask', Boolean, default=False),
        Column('help', Boolean, default=False),

    )
    meta.create_all(engine)


def ask_question(current_user, tablename):
    ask = tablename(user_id=current_user, ask=True, help=False)
    session.add(ask)
    session.commit()


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({'message': 'Token is missing'})

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(
                public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated


@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function!'})

    users = User.query.all()
    output = []
    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['email'] = user.email
        user_data['password'] = user.password
        user_data['gender'] = user.gender
        user_data['description'] = user.description
        user_data['admin'] = user.admin
        output.append(user_data)

    return jsonify({'users': output})


@app.route('/profile', methods=['GET'])
@token_required
def get_one_user(current_user):
    user = User.query.filter_by(name=current_user.name).first()
    if not user:
        return jsonify({'message': 'No user found!'})
    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['email'] = user.email
    user_data['password'] = user.password
    user_data['gender'] = user.gender
    user_data['description'] = user.description
    user_data['admin'] = user.admin

    return jsonify({'user': user_data})


@cross_origin()
@app.route('/register', methods=['POST'])
def register():
    name = request.json['name']
    email = request.json['email']
    password = request.json['password']
    gender = request.json['gender']
    description = request.json['description']
    hashed_password = generate_password_hash(password, method='sha256')
    if len(password) < 6:
        return make_response('Rövid jelszó', 400, {'WWWW-Authenticate': 'Basic realm="Rövid jelszó!"'})
    elif len(gender) < 2:
        return make_response('Kötelező nemet választani', 409, {'WWWW-Authenticate': 'Basic realm="Kötelező nemet választani!"'})
    elif User.query.filter_by(name=name).first() is not None:
        return make_response('A felhasználónév már a nyivántartásban van', 409, {'WWWW-Authenticate': 'Basic realm="Foglalt felhasználónév!"'})
    elif User.query.filter_by(email=email).first() is not None:
        return make_response('Az email foglalt', 409, {'WWWW-Authenticate': 'Basic realm="Foglalt email!"'})

    user = User(public_id=str(uuid.uuid4()), name=name, email=email,
                password=hashed_password, gender=gender, description=description, admin=False)
    db.session.add(user)
    db.session.commit()

    return jsonify({'message': "Felhasználó regisztrált", 'name': name, 'password': password})


@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def promote_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function!'})
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message': 'No user found!'})
    user.admin = True
    db.session.commit()

    return jsonify({'message': 'The user has been promoted!'})


@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function!'})
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message': 'No user found!'})

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message': 'The user has been deleted'})


@app.route('/login', methods=['POST'])
@cross_origin()
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWWW-Authenticate': 'Basic realm="Login required!"'})

    user = User.query.filter_by(name=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWWW-Authenticate': 'Basic realm="Bad credentials!"'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id': user.public_id, 'exp': datetime.datetime.utcnow(
        ) + datetime.timedelta(minutes=60)}, app.config['SECRET_KEY'])

        return jsonify({'token': token.decode('UTF-8')})

    return make_response('Could not verify', 401, {'WWWW-Authenticate': 'Basic realm="Login required!"'})


@app.route('/question', methods=['GET'])
@token_required
def get_all_question(self):
    subjects = Subject.query.all()
    output = []
    for subject in subjects:
        subject_data = {}
        subject_data['id'] = subject.id
        subject_data['text'] = subject.text
        output.append(subject_data)

    return jsonify({'subjects': output})


@app.route('/question/<question_id>', methods=['GET'])
@token_required
def get_one_question(current_user, question_id):
    question = Question.query.filter_by(
        id=question_id, user_id=current_user.id).first()
    if not question:
        return jsonify({'message': 'No question found!'})

    question_data = {}
    question_data['id'] = question.id
    question_data['text'] = question.text
    question_data['ask'] = question.ask
    question_data['help'] = question.help

    return jsonify(question_data)


@app.route('/question', methods=['POST'])
@token_required
def create_subject(current_user):
    data = request.get_json()
    new_question = Subject(text=data['text'])
    if Question.query.filter_by(text=data['text']).first() is not None:
        return make_response('Could not add question', 409, {'WWWW-Authenticate': 'Basic realm="Question already exists!"'})
    else:
        create_question_model(data['text'])
        db.session.add(new_question)
        db.session.commit()
        return jsonify({'message': 'Question created!'})


@app.route('/question/<question_id>', methods=['DELETE'])
@token_required
@cross_origin()
def delete_question(current_user, question_id):
    question = Question.query.filter_by(
        id=question_id, user_id=current_user.id).first()
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function!'})
    elif not question:
        return jsonify({'message': 'No todo found!'})
    db.session.delete(question)
    db.session.commit()

    return jsonify({'message': 'Question has deleted'})


# Kiegészíteni,hogy a felhasználó ne lehessen a saját segítője
@app.route('/ask/<question_text>', methods=['GET'])
@token_required
@cross_origin()
def ask(current_user, question_text):
    auth = request.authorization
    engine = create_engine('sqlite:///stunder_database.db', echo=True)

    subject = Subject.query.filter_by(text=question_text).first()

    if not subject:
        return make_response('Could not add question', 409, {'WWWW-Authenticate': 'Basic realm="No subject found"'})
    haveask = engine.execute(select(Question.id).where(Question.text == question_text).where(
        Question.asker == current_user.name).where(Question.helper == '')).fetchone()
    if haveask:
        return make_response('Could not add question', 409, {'WWWW-Authenticate': 'Basic realm="You already have a question"'})
    quer = engine.execute(select(Question.helper).where(
        Question.text == question_text).where(Question.asker == '')).fetchone()
    if quer is None:
        engine.execute(insert(Question).values(
            text=question_text, asker=current_user.name, status=True))
        return make_response('New ask record inserted', 201, {'WWWW-Authenticate': 'Basic realm="New record inserted"'})

    else:
        empty_asker_id = engine.execute(select(Question.id).where(
            Question.asker == '').where(Question.text == question_text)).first()
        # itt jön létre a chat
        # megkeresem azt a sort ahol üres a kérdező de van bent már segítő
        empty_asker = engine.execute(select(Question.helper).where(
            Question.asker == '').where(Question.text == question_text)).first()
        subject_data = {}
        subject_data['only_helper'] = empty_asker[0]
        subject_data['text'] = question_text
        subject_data['username'] = current_user.name
        update_statement = update(Question).where(
            Question.id == empty_asker_id[0]).values(asker=current_user.name)
        engine.execute(update_statement)

        return jsonify(subject_data)


@app.route('/help/<question_text>', methods=['GET'])
@token_required
@cross_origin()
def help(current_user, question_text):
    auth = request.authorization
    engine = create_engine('sqlite:///stunder_database.db', echo=True)

    subject = Subject.query.filter_by(text=question_text).first()
    if not subject:
        return jsonify({'message': 'No subject found!'})

    havehelp = engine.execute(select(Question.id).where(Question.text == question_text).where(
        Question.helper == current_user.name).where(Question.asker == '')).fetchone()
    if havehelp:
        return make_response('Could not add help', 409, {'WWWW-Authenticate': 'Basic realm="You already have a question"'})

    quer = engine.execute(select(Question.asker).where(
        Question.text == question_text).where(Question.helper == '')).fetchone()
    if quer is None:
        engine.execute(insert(Question).values(
            text=question_text, helper=current_user.name, status=True))
        return make_response('New ask record inserted', 201, {'WWWW-Authenticate': 'Basic realm="New record inserted"'})
      # először megkeresem azt az id-t amelynél üres
    else:
        empty_helper_id = engine.execute(select(Question.id).where(
            Question.helper == '').where(Question.text == question_text)).first()

        update_statement = update(Question).where(
            Question.id == empty_helper_id[0]).values(helper=current_user.name)
        empty_helper = engine.execute(select(Question.asker).where(
            Question.helper == '').where(Question.text == question_text)).first()
        subject_data = {}
        subject_data['only_helper'] = empty_helper[0]
        subject_data['text'] = question_text
        subject_data['username'] = current_user.name
        engine.execute(update_statement)

        return jsonify(subject_data)


if __name__ == '__main__':
    app.run()
