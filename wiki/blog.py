# coding: utf-8
import os
import re
import logging 

import random
import hashlib
import hmac
from string import letters
from datetime import datetime,timedelta

import jinja2
import webapp2

from google.appengine.ext import db
from google.appengine.api import memcache 

secret = 'iamsecret'

logging.basicConfig(level=logging.DEBUG)
template_dir = os.path.join(os.path.dirname(__file__),'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
	autoescape = True)


# user_id hash and cookie
def render_str(template,**params):
	t = jinja_env.get_template(template)
	return t.render(params)

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
def  valid_pw(name,password,h): # 在登录页会检查密码 hash
	salt = h.split(',')[0]
	return h == make_pw_hash(name,password,salt)

# 封装memcache set, 现在的时间作为值
def age_set(key,val):
	save_time = datetime.utcnow()
	memcache.set(key,(val,save_time))

# 封装memcache get
def age_get(key):
	r = memcache.get(key)
	if r:
		val, save_time = r
		age = (datetime.utcnow()-save_time).total_seconds()
	else:
		val,age = None,0
	return val,age

def add_post(ip,post):
	post.put()
	get_posts(update = True)
	return str(post.key().id())

def get_posts(update=False):
	q = Post.all().order('-created').fetch(limit=10)
	mc_key = 'BLOGS'

	posts,age = age_get(mc_key)
	if update or posts is None:
		posts = list(q)
		age_set(mc_key,posts)

	return posts,age

def age_str(age):
	s = 'queried %s seconds ago'
	age = int(age)
	if age == 1:
		s = s.replace('seconds','second')
	return s % age

class Handler(webapp2.RequestHandler):
	def write(self,*a,**kw):
		self.response.write(*a,**kw)
	def render_str(self,template,**params):
		return render_str(template,**params)
	def render(self,template,**kw):
		self.write(self.render_str(template,**kw))

	def set_secure_cookie(self,name,val):
		cookie_val = make_secure_val(val)
		self.response.headers.add_header('Set-Cookie','%s=%s;Path=/'%(name,cookie_val))
	def read_secure_cookie(self,name):
		cookie_val = self.request.cookies.get(name)
		return cookie_val and check_secure_val(cookie_val)

	def login(self,user):# 添加‘Set-Cookie: user_id = kasfhwekaw’ 到浏览器
		self.set_secure_cookie('user_id',str(user.key().id()))
	def logout(self):
		self.response.headers.add_header('Set-Cookie','user_id=;Path=/') # override the same cookie
	def initialize(self,*a,**kw):
		webapp2.RequestHandler.initialize(self,*a,**kw)
		uid = self.read_secure_cookie('user_id')
		self.user = uid and User.by_id(int(uid))

def users_key(group = 'default'):
	return db.Key.from_path('users',group)

# ---database---
# user表单
class User(db.Model):
	name = db.StringProperty(required = True)
	pw_hash = db.StringProperty(required = True)
	email = db.StringProperty()

	@classmethod 
	def by_id(cls,uid):
		return User.get_by_id(uid, parent = users_key())

	@classmethod
	def by_name(cls,name):
		u = User.all().filter('name =',name).get()
		return u
	
	# creates the object(User)
	@classmethod
	def register(cls,name,pw,email=None):
		pw_hash = make_pw_hash(name,pw)
		return User(parent = users_key(),
					name = name,
					pw_hash = pw_hash,
					email = email)

	@classmethod
	def login(cls,name,pw): # 在登录页会检查密码 hash
		u = cls.by_name(name)
		if u and valid_pw(name, pw, u.pw_hash):
			return u




# post表单
class Post(db.Model):
	subject = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)

	def render(self):
		self._render_text = self.content.replace('\n','<br>')
		return render_str("post.html",p=self)

def blog_key(name = "default"):
	return db.Key.from_path('blogs',name)


# ---blog url render---

class BlogFront(Handler): # ('/blog/?',BlogFront) 主页
	def get(self):
		#posts = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC")
		posts,age = get_posts()
		self.render('front.html',posts = posts,age = age_str(age))

class PostPage(Handler): #('/blog/([0-9]+)',PostPage) 一篇blog单独页
	def get(self, post_id):
		#key = db.Key.from_path('Post',int(post_id),parent=blog_key())
		#post = db.get(key)
		post_key = 'POST_'+post_id
		logging.info("PostPage_post_key: %s" % post_key)
		post,age = age_get(post_key)
		if not post:
			key = db.Key.from_path('Post',int(post_id),parent=blog_key())
			logging.info("PostPage_key: %s" % key)
			post = db.get(key)
			logging.info("PostPage_key: %s" % key)
			age_set(post_key,post)
			age = 0

		if not post:
			self.error(404)
			return

		self.render("permalink.html",post=post,age = age_str(age))


class NewPost(Handler): # ('/blog/newpost',NewPost) 新增一篇博文
	def get(self):
		self.render("newpost.html")
	def post(self):
		subject = self.request.get("subject")
		content = self.request.get("content")

		if subject and content:
			p = Post(parent = blog_key(),subject=subject, content=content)
			logging.info("NewPost_p: %s" % p)
			p.put()
			self.redirect("/blog/%s" %str(p.key().id()))
		else:
			error = "we need both a subject and some contents!"
			self.render("newpost.html",subject=subject,content=content,error=error)

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



class Signup(Handler): # 注册页的根类

    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else: 
            self.done()

    def done(self,*a,**kw): # 提交表单
    	raise NotImplementedError # 在实例化对象Register中将要被覆写


class Register(Signup): # ('/signup',Register) 实例化注册页
	def done(self): #override func done 覆写，提交表单到服务器
		# 检查提交的用户名是否存在
		u = User.by_name(self.username)
		if u: # 用户名存在，输出错误
			msg = "That user already exists."
			self.render('signup-form.html', error_username = msg)
		else: # 新用户
			u = User.register(self.username,self.password,self.email) # 实例化User类
			u.put() # 存入数据库

			self.login(u) # 添加‘Set-Cookie: user_id = kasfhwekaw’ 到浏览器,Handler func
			self.redirect('/blog/welcome')

class Welcome(Handler):
	def get(self):
		if self.user:
			self.render('welcome.html',username = self.user.name)
		else:
			self.redirect('/signup')

# ---login logout 登录登出---

class Login(Handler): # ('/login',Login) 登录页
	def get(self):
		self.render('login-form.html')

	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')

		u = User.login(username,password) # 在登录页会检查密码 hash 匹配
		if u:
			self.login(u) # 添加‘Set-Cookie: user_id = kasfhwekaw’ 到浏览器,Handler func
			self.redirect('/blog')
		else:
			msg = 'Invald  Login'
			self.render('login-form.html',error = msg)

class Logout(Handler):
	def get(self):
		self.logout()
		self.redirect('/signup') # 重定向到注册页


app = webapp2.WSGIApplication([
	('/blog/?',BlogFront),
	('/blog/([0-9]+)',PostPage),
	('/blog/newpost',NewPost),
	('/signup',Register),
	('/login',Login),
	('/logout',Logout),
	('/blog/welcome',Welcome),
	],
	debug=True)