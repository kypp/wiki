import os
import re
import webapp2
import jinja2
import hmac
import json
import logging
from time import time

from google.appengine.ext import db
from google.appengine.api import memcache


# CONSTANTS
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(
	loader=jinja2.FileSystemLoader(template_dir),
	autoescape = False)

# HANDLER
class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.write(*a, **kw)

	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

# cookies and auth

def blog_key(name = 'default'):
	return db.Key.from_path('blogs', name)

TAJNE = "uggughnaughtttt"
def hash_id(id):
	return id + '|' + hmac.new(str(id), str(TAJNE)).hexdigest()

def check_id(h):
	if not h:
		return None
	id = h.split('|')[0]
	if hash_id(id) == h:
		return id
	return None

class User(db.Model):
	name = db.StringProperty(required = True)
	password = db.StringProperty(required = True)
	email = db.StringProperty()

def by_id(id):
	return User.get_by_id(int(id)) if id else None

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
	return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
	return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
	return not email or EMAIL_RE.match(email)

# SIGNUP AND LOGIN

class Signup(Handler):

	def get(self):
		self.render("signup-form.html")

	def post(self):
		have_error = False
		username = self.request.get('username')
		password = self.request.get('password')
		verify = self.request.get('verify')
		email = self.request.get('email')

		params = dict(username = username,
					  email = email)

		q = db.GqlQuery('SELECT * FROM User WHERE name = :1', username)

		if q.count() > 0:
			params['error_username'] = "Such a user already exysts!"
			have_error = True

		elif not valid_username(username):
			params['error_username'] = "That's not a valid username."
			have_error = True

		if not valid_password(password):
			params['error_password'] = "That wasn't a valid password."
			have_error = True
		elif password != verify:
			params['error_verify'] = "Your passwords didn't match."
			have_error = True

		if not valid_email(email):
			params['error_email'] = "That's not a valid email."
			have_error = True

		if have_error:
			self.render('signup-form.html', **params)
		else:
			u = User(name = username, password = password, email = email)
			u.put()
			self.response.headers.add_header('Set-Cookie', 'user-id=%s;Path=/' % hash_id(str(u.key().id())))
			self.redirect('/')

class Login(Handler):
	def get(self):
		self.render("login-form.html")
	def post(self):
		have_error = False
		username = self.request.get('username')
		password = self.request.get('password')

		params = dict(username = username)

		q = db.GqlQuery('SELECT * FROM User WHERE name = :1', username)
		user = None
		for u in q:
			user = u
		if not user:
			params['error_username'] = "There exysts none such user!"
			have_error = True
		elif user.password != password:
			params['error_password'] = "Such password is a wrong password for such user!"
			have_error = True

		if have_error:
			self.render('login-form.html', **params)
		else:
			self.response.headers.add_header('Set-Cookie', 'user-id=%s;Path=/' % hash_id(str(user.key().id())))
			self.redirect('/')

class Logout(Handler):
	def get(self):
		self.response.headers.add_header('Set-Cookie', 'user-id=;Path=/')
		self.redirect('/')


# PAGES

class Page(db.Model):
	name = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)

class EditPage(Handler):
	def get(self, page_name):
		id = check_id( self.request.cookies.get('user-id') )
		if not id:
			self.redirect('/signup')
		else:
			page = db.GqlQuery("SELECT * FROM Page WHERE name = :1 ORDER BY created DESC", page_name).get()
			self.render('edit.html', pagename = page_name, content = page.content if page else "", user = by_id(id))

	def post(self, page_name):
		id = check_id( self.request.cookies.get('user-id') )
		if not id:
			self.redirect('/signup')
		else:
			content = self.request.get('content')
			page = Page(name = page_name, content = content)
			page.put()
			memcache.set(page_name, page.content)
			self.redirect(page_name)

class WikiPage(Handler):
	def get(self, page_name):
		id = check_id( self.request.cookies.get('user-id') )
		v = int(self.request.get('v', 0))
		if not v:
			v = 0
		#content = memcache.get(page_name)
		#if not content:
		page = db.GqlQuery("SELECT * FROM Page WHERE name = :1 ORDER BY created %s" % ("DESC" if v==0 else "ASC"), page_name).get(offset = v if v==0 else v-1)
		#if page:
			#content = page.content
			#memcache.set(page_name, page.content)

		if not page:
			self.redirect('/_edit%s' % page_name)
		else:
			self.render('page.html', pagename = page_name, content = page.content, user = by_id(id))

class HistoryPage(Handler):
	def get(self, page_name):
		id = check_id( self.request.cookies.get('user-id') )
		history = list(db.GqlQuery("SELECT * FROM Page WHERE name = :1 ORDER BY created DESC", page_name).run())
		self.render('history.html', pagename = page_name, user = by_id(id), history = history)

class Jezus(Handler):
	def get(self):
		self.write("Jezus")

PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
app = webapp2.WSGIApplication([
								('/jezus', Jezus),
								('/signup', Signup),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/_edit' + PAGE_RE, EditPage),
                               ('/_history' + PAGE_RE, HistoryPage),
                               (PAGE_RE, WikiPage)
], debug=True)