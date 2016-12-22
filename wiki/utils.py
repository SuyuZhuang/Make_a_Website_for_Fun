#coding: utf-8
# for login and signup
import re
import os

import jinja2

import random
import hashlib
import hmac
from string import letters
from datetime import datetime,timedelta

import logging # 日志输出


logging.basicConfig(level=logging.DEBUG)
template_dir = os.path.join(os.path.dirname(__file__),'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
	autoescape = True)

PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
secret = 'iamsecret'

def render_str(template,**params):
	t = jinja_env.get_template(template)
	return t.render(params)
# user_id hash and cookie
def make_secure_val(val):
	return '%s|%s' % (val,hmac.new(secret,val).hexdigest())

def check_secure_val(secure_val):
	val = secure_val.split('|')[0]
	if secure_val == make_secure_val(val):
		return val

# user password hashing
def make_salt(length=5):
	return ''.join(random.choice(letters) for x in xrange(length))
def make_pw_hash(name, pw, salt=None):
	if not salt:
		salt = make_salt()
	h = hashlib.sha256(name+pw+salt).hexdigest()
	return '%s,%s' %(salt, h)
def valid_pw(name,password,h): # 在登录页会检查密码 hash
	salt = h.split(',')[0]
	return h == make_pw_hash(name,password,salt)


# ---signup 注册---
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)