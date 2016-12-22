#coding: utf-8
from google.appengine.ext import ndb
from utils import *

# Page database
def wiki_key(name="default"):
	return ndb.Key('pages',name)

class Page(ndb.Model):
	content = ndb.TextProperty(repeated = True)
	created = ndb.DateTimeProperty(auto_now_add = True)
	date_modified = ndb.DateTimeProperty(repeated = True)
	def render_content(self,version):
		self._render_text = self.content[version-1].replace('\n','<br>')
		return render_str("content.html",p=self) # html 中就是p._render_text

	def update(self,content):
		date_mod = datetime.datetime.now()
		self.content.append(content)
		self.date_modified.append(date_mod)
		return self

	@classmethod
	def get_page(cls,pagename):
		wiki_page = cls.by_page_key(pagename)
		return wiki_page

	@classmethod
	def by_page_key(cls,pagename):
		wiki_page = cls.get_by_id(pagename, parent = wiki_key())
		return wiki_page

	@classmethod
	def construct(cls,content,pagename):
		date_mod = datetime.datetime.now()
		return cls(parent = wiki_key(),
			content = content,
			date_modified = date_mod,
			id = pagename)


# user表单
def users_key(group = 'default'):
	return ndb.Key('users',group)

class User(ndb.Model):
	name = ndb.StringProperty(required = True)
	pw_hash = ndb.StringProperty(required = True)
	email = ndb.StringProperty()

	@classmethod 
	def by_id(cls,uid):
		return User.get_by_id(uid, parent = users_key())

	@classmethod
	def by_name(cls,name):
		#u = User.all().filter('name =',name).get()
		u = User.query(User.name==name).get()
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