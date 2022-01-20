from enum import unique
from hashlib import md5
from importlib import resources
import json
from flask import Flask, jsonify, make_response, request
from werkzeug.security import generate_password_hash,check_password_hash
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
import uuid
import jwt
import datetime
from flask_cors import CORS,cross_origin
#https://www.youtube.com/watch?v=WxGBoY5iNXY
#https://www.youtube.com/watch?v=2VXQL3Pk0Bs

app=Flask(__name__)
CORS(app)



app.config['SECRET_KEY']='thisissecret'
app.config['SQLALCHEMY_DATABASE_URI'] ='sqlite:///stunder.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=True

db=SQLAlchemy(app)

class User(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    public_id=db.Column(db.String(50),unique=True)
    name=db.Column(db.String(50))
    password=db.Column(db.String(80))
    admin=db.Column(db.Boolean)
    
class Question(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    text=db.Column(db.String(50))
    ask=db.Column(db.Boolean)
    help=db.Column(db.Boolean)
    user_id=db.Column(db.Integer)
    
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token=None
        
        if 'x-access-token' in request.headers:
            token=request.headers['x-access-token']
        if not token:
            return jsonify({'message': 'Token is missing'})
        
        try:
            data= jwt.decode(token,app.config['SECRET_KEY'])
            current_user=User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message':'Token is invalid!'}),401
        
        return f(current_user,*args,**kwargs)
    
    return decorated 


@app.route('/user',methods=['GET'])
@token_required
def get_all_users(current_user):
    
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function!'})
    
    
    users=User.query.all()
    output=[]
    for user in users:
        user_data={}
        user_data['public_id']=user.public_id
        user_data['name']=user.name
        user_data['password']=user.password
        user_data['admin']=user.admin
        output.append(user_data)
    
    
    
    return jsonify({'users': output})

@app.route('/user/<public_id>',methods=['GET'])
@token_required
def get_one_user(current_user,public_id):
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function!'})
    
    user=User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message':'No user found!'})
    user_data={}
    user_data={}
    user_data['public_id']=user.public_id
    user_data['name']=user.name
    user_data['password']=user.password
    user_data['admin']=user.admin
    
    return jsonify({'user':user_data})

@app.route('/user',methods=['POST'])
@token_required
def create_user(current_user):
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function!'})
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({'message':'New user created'})

@app.route('/user/<public_id>',methods=['PUT'])
@token_required
def promote_user(current_user,public_id):
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function!'}) 
    user=User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message':'No user found!'})
    user.admin=True
    db.session.commit()
    
    return jsonify({'message':'The user has been promoted!'})
    
    

@app.route('/user/<public_id>',methods=['DELETE'])
@token_required
def delete_user(current_user,public_id):
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function!'}) 
    user=User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message':'No user found!'})
    
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message':'The user has been deleted'})

@app.route('/login', methods=['GET'])
@cross_origin()
def login():
    auth=request.authorization
    
    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify',401,{'WWWW-Authenticate':'Basic realm="Login required!"'})

    user=User.query.filter_by(name=auth.username).first()
    
    if not user:
        return make_response('Could not verify',401,{'WWWW-Authenticate':'Basic realm="Login required!"'})

    if check_password_hash(user.password,auth.password):
        token=jwt.encode({'public_id':user.public_id,'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},app.config['SECRET_KEY'])
        
        return jsonify({'token': token.decode('UTF-8')})
    
    
    return make_response('Could not verify',401,{'WWWW-Authenticate':'Basic realm="Login required!"'})
  
@app.route('/question',methods=['GET'])
@token_required
def get_all_question(current_user):
    questions=Question.query.filter_by(user_id=current_user.id).all()
    output=[]
    for question in questions:
        question_data={}
        question_data['id']=question.id
        question_data['text']=question.text
        question_data['ask']=question.ask
        question_data['help']=question.help
        output.append(question_data)
    
    return jsonify({'questions': output})

@app.route('/question/<question_id>',methods=['GET'])
@token_required
def get_one_question(current_user,question_id):
    question=Question.query.filter_by(id=question_id,user_id=current_user.id).first()
    if not question:
        return jsonify({'message':'No question found!'})
    
    question_data={}
    question_data['id']=question.id
    question_data['text']=question.text
    question_data['ask']=question.ask
    question_data['help']=question.help
  
    
    return jsonify(question_data)

@app.route('/question', methods=['POST'])
@token_required
def create_question(current_user):
    data=request.get_json()
    
    new_question=Question(text=data['text'],ask=False,help=False,user_id=current_user.id)
    db.session.add(new_question)
    db.session.commit()
    
    return jsonify({'message':'Question created!'})

# @app.route('/question/<question_id>',methods=['PUT'])
# @token_required
# def complete_todo(current_user,question_id):
#     question=Question.query.filter_by(id=question_id,user_id=current_user.id).first()
#     if not question:
#         return jsonify({'message':'No question found!'})
    
#     question.complete=True
#     db.session.commit()
    
#     return jsonify({'message':'Todo item has been completed'})
    
  

@app.route('/question/<question_id>',methods=['DELETE'])
@token_required
def delete_question(current_user,question_id):
    question=Question.query.filter_by(id=question_id,user_id=current_user.id).first()
    if not question:
        return jsonify({'message':'No todo found!'})
    
    db.session.delete(question)
    db.session.commit()
    
    return jsonify({'message':'Question has deleted'})

  
    
if __name__ =='__main__':
    app.run()#debug=True)