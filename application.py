import string
import random
import smtplib
import datetime
import os
import locale
import sys
import json
import re
import hashlib
import configparser
from functools import wraps
from flask import Flask,request, Response
from flask.ext.api import status
from flask.ext.cors import CORS, cross_origin
from sqlalchemy import Column, ForeignKey, Integer, String, DateTime, Boolean, create_engine
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.schema import CreateTable
from sqlalchemy.ext.declarative import declarative_base
from email.mime.text import MIMEText

app = Flask(__name__)
cors = CORS(app)
app.config['CORS_HEADERS'] = 'Content-Type'

db_session = None

SALT_A = ""
SALT_B = ""
MAILER_KEY = ""
HIMACHO_MAIL_ADDRESS = ""
HIMACHO_MAIL_PASSWORD = ""


#### Helper ####

# Basic Authorization
def check_auth(username, password):
    token = db_session.query(Token).filter(Token.api_token == username, Token.api_token_secret==password).all()
    return len(token) == 1


def authenticate():
    return Response(
    'Could not verify your access level for that URL.\n'
    'You have to login with proper credentials', 401,
    {'WWW-Authenticate': 'Basic realm="Login Required"'})


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated


# メール送信
def send_register_mail(mail, sign_up_code):
    from_addr = HIMACHO_MAIL_ADDRESS
    password = HIMACHO_MAIL_PASSWORD
    titletext = "😤[beshop]登録完了🏃🏃🏃🏃🏃"
    body = """
    beshopへの登録ありがとうございました🙆
    以下のurlへアクセスして最高貸し借りライフを始めめよう💪


    http://example.com?sign_up_code=""" + sign_up_code + """

    🌴🌴🌴🌴🌴🌴💃🌴🌴🌴🌴🌴🌴
    share everything, beshop.
    """

    # メールオブジェクトの生成
    encoding = 'utf-8'
    msg = MIMEText( body.encode( encoding ), 'plain', _charset=encoding )
    msg['Subject'] = titletext
    msg['From'] = from_addr
    msg['To'] = mail

    # メール送信
    s = smtplib.SMTP('smtp.zoho.com',587)
    s.ehlo()
    s.starttls()
    s.ehlo()
    s.login(from_addr, password)
    s.send_message(msg)
    s.close()


#　ランダム文字列
def random_str(length):
    return ''.join([random.choice(string.ascii_letters + string.digits) for i in range(length)])


# token生成
def gen_token(user):
    token_dict = {}
    api_token = random_str(128)
    api_token_secret = random_str(128)
    token_dict['api_token'] = api_token
    token_dict['api_token_secret'] = api_token_secret

    token = Token(api_token=api_token, api_token_secret=api_token_secret, user=user)

    db_session.add(token)
    db_session.commit()

    return token_dict


def gen_salted_hash(target):
    hashed_password= hashlib.sha512()
    hashed_password.update( str.encode(SALT_A) )
    hashed_password.update( str.encode(target) )
    hashed_password.update( str.encode(SALT_B) )
    return hashed_password.hexdigest()


#### Model ####

Base = declarative_base()

# class User(Base):
#     __tablename__ = 'user'
#     id = Column(Integer, primary_key=True)
#     username = Column(String(250), nullable=True)
#     mail = Column(String(250), nullable=False)
#     facebook_id = Column(String(250),nullable=True)
#     password = Column(String(250), nullable=True)
#     sign_up_code= Column(String(250), nullable=False)
#     sign_up_code_expire = Column(DateTime(), nullable=False)
#     registerd = Column(Boolean(), nullable=False)
#
# class Token(Base):
#     __tablename__ = 'token'
#     id = Column(Integer, primary_key=True)
#     api_token = Column(String(250), nullable=False)
#     api_token_secret = Column(String(250), nullable=False)
#     user_id = Column(Integer, ForeignKey('user.id'), nullable=False)
#     user = relationship(User)


#### Controller ####

@app.route('/', methods=['GET'])
@cross_origin()
def test_sendmail():
    mail = "onomotoharu@gmail.com"
    sign_up_code = random_str(128)
    send_register_mail(mail, sign_up_code)

    return "{}", status.HTTP_200_OK




def configure():
    # Config load
    global SALT_A
    global SALT_B
    global MAILER_KEY
    global HIMACHO_MAIL_ADDRESS
    global HIMACHO_MAIL_PASSWORD
    inifile = configparser.ConfigParser()
    inifile.read("./config.ini")
    SALT_A = inifile.get("config","SALT_A")
    SALT_B = inifile.get("config","SALT_B")
    HIMACHO_MAIL_ADDRESS = inifile.get("mail","ADDRESS")
    HIMACHO_MAIL_PASSWORD = inifile.get("mail","PASSWORD")

    # DB
    global db_session
    host = inifile.get("db_host","HOST")
    user = inifile.get("db_host","USER")
    password = inifile.get("db_host","PASSWORD")

    target = "mysql+mysqlconnector://" + user + "@" + host + "/beshop"
    engine = create_engine(target, convert_unicode=True)
    Base.metadata.create_all(engine)
    Base.metadata.bind = engine
    DBSession = sessionmaker(bind=engine)
    db_session = DBSession()


if __name__ == '__main__':
    configure()
    app.run(debug=True)
