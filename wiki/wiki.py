#coding: utf-8

import datetime
# 两个需要用到的模版

import webapp2 



from ndbmodels import *
from utils import *


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
		self.set_secure_cookie('user_id',str(user.key.id()))
	def logout(self):
		self.response.headers.add_header('Set-Cookie','user_id=;Path=/') # override the same cookie
	def initialize(self,*a,**kw):
		webapp2.RequestHandler.initialize(self,*a,**kw)
		uid = self.read_secure_cookie('user_id')
		self.user = uid and User.by_id(int(uid))

#--- Page Handler ---
class PageHandler(Handler): # root Handler for Page
	def read_version(self,wikipage):
		if wikipage:
			version = self.request.get('v')
			logging.info("read_version_in_def:%s" %version)
			if (version and version.isdigit() and int(version)<=len(wikipage.content)):
				version = int(version)
			else:
				# 如果version不是数字，we default to the lastest version
				version = len(wikipage.content)
				logging.info("read_version_in_def_after_ass:%s" %version)
				logging.info("read_version_wikipage.content:%s" %wikipage.content)
				logging.info("read_version_len(wikipage.content):%s" %len(wikipage.content))
			return version


class EditPage(PageHandler): #EditPage Handler for  '/_edit'+PAGE_RE
	def get(self,pagename):
		if self.user:
			logging.info("editpage_get pagename:%s" % pagename)
			page = Page.get_page(pagename)
			version = self.read_version(page)
			logging.info("editpage_get page:%s" % page)
			#logging.info("editpage_get page.content:%s" % page.content)
			self.render("editpage.html",title = 'Edit - %s' % pagename[1:],wikipage=page,version = version,user=self.user)
		else:
			self.redirect('/_login')


	def post(self,pagename):
		if self.user:
			content = self.request.get("content")
			logging.info("post content: %s" % content)
			if content:
				page = Page.get_page(pagename)
				date_mod = datetime.datetime.now()
				if page:
					page = page.update(content)
					logging.info("page update: %s" % page)
					page.put()
				else:
					page = Page.construct(content,pagename)
					#date_mod = datetime.datetime.now()
					#page = Page(parent = wiki_key(),content = content,date_modified = date_mod,id = pagename)
					logging.info("page construct: %s" % page)
					page.put()
				self.redirect(pagename)
			else:
				error = "Content required!!"
				self.render("editpage.html",error = error,user=self.user)
		else:
			self.redirect('/_login')


class WikiPage(PageHandler): #WikiPage Handler 显示最近修改的Page
	def get(self,pagename):
		logging.info("WikiPage_get_pagename= %s" % pagename)
		page = Page.get_page(pagename)
		logging.info("WikiPage_page= %s" % page)

		if not page:
			if self.user:
				self.redirect("/_edit%s" % pagename)
			else:
				self.redirect('/_login')
		else:
			logging.info("page_title: %s" %pagename[1:])
			version = self.read_version(page)
			logging.info("WikiPage_page_self.user= %s" % self.user)
			logging.info("WikiPage_page_self.user.username= %s" % self.user)
			self.render("wikipage.html",wikipage = page,title=pagename[1:],version = version,user=self.user)


class HistoryPage(PageHandler): #Hitory Handler 显示所有更改的版本
	def get(self,pagename):
		page = Page.get_page(pagename)
		self.render("history.html",title = 'History -%s' % pagename[1:],wikipage = page,user=self.user)






#--- 注册登录Handler ---
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
			self.redirect('/')


# ---login logout 登录登出---

class Login(Handler): # ('/login',Login) 登录页
	def get(self):
		logging.info('login!!!')
		self.render('login-form.html')

	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')

		u = User.login(username,password) # 在登录页会检查密码 hash 匹配
		if u:
			self.login(u) # 添加‘Set-Cookie: user_id = kasfhwekaw’ 到浏览器,Handler func
			self.redirect('/')
		else:
			msg = 'Invald  Login'
			self.render('login-form.html',error = msg)

class Logout(Handler):
	def get(self):
		self.logout()
		self.redirect('/') # 重定向到注册页



app = webapp2.WSGIApplication([
	('/_edit'+PAGE_RE, EditPage), 
	('/_history' + PAGE_RE, HistoryPage),
	('/signup', Register), 
	('/login', Login), 
	('/logout', Logout), 
	(PAGE_RE, WikiPage),
	], debug=True)
	