from google.appengine.api import memcache
from google.appengine.ext import db
from time import sleep
import re
from random import shuffle
from string import letters
from hashlib import sha512
import hmac
import logging
import jinja2
import webapp2
import ast
import os

templates_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(templates_dir), autoescape=True)
SECRET = 'VBpZ6pCtt3mHLrcaGved2mL9fbf92ab5a8cfd5744890fbd8cbc723c7c225cf8ad5b172fe6618d47f5453d7ceb889fbc2a1fa391e4a61f80da56fce81b51b62fa62fa3f68b6c2e3bc17533b3'
USERNAME = None



def find_pos(keys, val):
	for pos in xrange(len(keys)):
		if str(keys[pos]) == str(val):
			return pos

def get_month_and_year(date):
	'''Takes a date and returns the year and month'''
	year, month = date.split('-')[:-1]
	return str(year), str(month)
		
def order_by_days(days):
	"""order_by_days(list) -> return(list)
	Returns a list that is sorted by the order of days in a week
	"""
	order_days = {'Monday': 1,    'Tuesday' : 2, 'Friday': 5, 
	              'Wednesday': 3, 'Thursday': 4, 'Sunday': 7, 
	              'Saturday': 6}
	return sorted(days, key=order_days.__getitem__)

def translate_month(month):
	'''translate_month(str) -> return(str)
	Takes a string digit and returns the month equivalent of that
	string.

	>>> translate_month(01)
	'January'
	'''
	months = {'01': 'January', '02':'February', '03':'March', 
		      '04': 'April',   '05':'May',      '06': 'June', 
		      '07':'July',     '08': 'August',  '09':'September',
	          '10':'October',  '11':'November', '12': 'December'}
	return months[month]

class BaseHandler(webapp2.RequestHandler):

	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def _render_template(self, template, **kw):
		template = jinja_env.get_template(template)
		return template.render(kw)

	def render(self, template, **kw):
		self.write(self._render_template(template, **kw))

class FAQ(BaseHandler):

	def get(self):
		self.render('/faq.html', user=USERNAME)

class Cookies(BaseHandler):
	def __init__(self, request, response):
		self.initialize(request, response)
		self.user_cookie = self.check_cookie()

	def delete_my_cookie(self):
		self.response.delete_cookie('user_id')

	def get_my_cookie(self):
		'''Return a cookie string'''
		return self.request.cookies.get('user_id')

	def make_cookie(self, obj):
		'''Create a secure cookie'''
		cookie_str = str(obj.key().id()) + Security.get_salt() # make a cookie string
		return Security.make_secure_str(cookie_str)            # return a secure cookie string

	def set_my_cookie(self, cookie):
		'''Set the web page to that cookie'''
		self.response.set_cookie('user_id', cookie, path='/')

	def check_cookie(self):
		'''Check whether the cookie been tampered with
		Return True if cookie has not been tampered with else
		return False
		'''

		cookie_str = self.get_my_cookie()
		if cookie_str:
			string = cookie_str.split('|')[0] # get the string part of the value from the cookoe hash
			return cookie_str == Security.make_secure_str(string)
		return None

class Cache(object):
	"""Cache the JobDetails_detailsbase for easy viewing"""

	@classmethod
	def search(cls):
		print '[+] Quering cache for information, please wait...'
		cache = memcache.get(USERNAME)
		if cache:
			print '[+] Information found and retreived from the cache'
			return cache
		else:
			print '[-] No information found in cache.'

	@classmethod
	def update_cache(cls, job_obj):
		print '[+] Updated cache table with new entry.'
		memcache.set(USERNAME, job_obj)
		
	@classmethod
	def add(cls, job_obj):
		print '[+] Added a new entry to the cache table.'
		memcache.add(USERNAME, job_obj)

class SignUp(Cookies):

	def get(self):
		if self.user_cookie:
			self.delete_my_cookie()
		self.render('/signUp.html')

	def post(self):

		name     = self.request.get('name')
		password = self.request.get('password')
		verify_password = self.request.get('verify')
		email = self.request.get('email')
		self.process_form(str(name.title()), password, verify_password, email)

	def process_form(self, name, password, verify_password, email=None):

		if (name and password and verify_password) and \
		     VerificationHandler.valid_username(name) and \
		     VerificationHandler.valid_passwd(password):

			if password != verify_password:
				self.render('/signUp.html', name=name, passwd_error='The password do not match')
			else:

				if not UsersDetailsDb.search(name):
					encrypted_passwd = Security.encrypt(name, password)
			 		usr_obj = UsersDetailsDb.add(name, encrypted_passwd)
			 		self.set_my_cookie(self.make_cookie(usr_obj))
					global USERNAME 
					USERNAME = name
					self.redirect('/JobDetails')
			 	else:
			 		self.render('/signUp.html', name_error='The username by that name already exists!!!')
			 		print 'here'

		else:

			self.render('/signUp.html', msg='Invalid username and password!!!')

class UsersDetailsDb(db.Model):

	name = db.StringProperty(required=True)
	password = db.StringProperty(required=True)
	email = db.EmailProperty()

	@classmethod
	def add(cls, name, password, email=None):
		user_db = cls(name=name, password=password, email=email)
		user_db.put()
		return user_db

	@classmethod
	def search(cls, name):
		return cls.all().filter('name =', name).get()

class JobDetailsDb(db.Model):
	"""Holds the user job details"""	

	
	JobDetails_details  = db.StringProperty(required=True)
	created = db.DateTimeProperty(auto_now=True)
	last_created = db.DateTimeProperty(auto_now_add=True)
	username = db.StringProperty(required=True)
	
	@classmethod
	def add(cls, JobDetails_details):
		print '[+] Adding new entry to database.'
		weeks_obj = cls(JobDetails_details=str(JobDetails_details), 
			            username=USERNAME)
		weeks_obj.put()
		Cache.add(weeks_obj)
	
	@classmethod	
	def update(cls, obj, data):
		print'[+] Updating the entries in the database.'
		obj.JobDetails_details = str(data)
		obj.put()
		Cache.update_cache(obj)
	
class NewWeek(Cookies):

	def get(self):

		if self.user_cookie:
			self.redirect('/JobDetails')
		else:
			self.redirect('/login')

class Calculate(object):

	@classmethod
	def get_sum(cls, job_details, key):
		days = job_details.keys()
		return '%.2f'%(sum([float(job_details[day]['Job_details'][key]) for day in days]))

	@classmethod
	def get_daily_pay(cls, hours, hourly_pay):

		hours = str(float(hours))
		hrs, mins = hours.split('.')
		hours = int(hrs) + (int(mins)/60.0)
		return '%.2f' %((hours * float(hourly_pay)))

	@classmethod
	def get_weekly_payment(cls, job_details):
		return cls.get_sum(job_details,'weekly_payment')

	@classmethod
	def get_additionl_payment(cls, job_details):
		return cls.get_sum(job_details,'additional_payment')

	@classmethod
	def get_mins(cls, start_time, finish_time):
		finish_time_mins = int(finish_time.split(':')[1]) 
		start_time_mins  = int(start_time.split(':')[1])

		if not finish_time_mins:
			finish_time_mins = 60
		if not start_time_mins:
			start_time_mins = 60

		return abs(start_time_mins - finish_time_mins)
		
	@classmethod
	def get_hours(cls, start_time, finish_time):
		if start_time < finish_time:
			return int(finish_time.split(':')[0]) - int(start_time.split(':')[0])
		else:
			start_time = int(start_time.split(':')[0])

			# Calculates the number of hours when the start time is greater or equal to finish time,
			# by changing the start time to a 12 hrs format and the finish time to a 24 hrs format. 
			# Subtract the finish time and start time to get the total number of hours between the two
			start_time -= 12 # change to 12 hr format
			finish_time = int(finish_time.split(':')[0]) + 12 # change to 24 hr format
			return finish_time - start_time

	@classmethod
	def get_total_hours(cls, start_time, finish_time):
		hours = cls.get_hours(start_time, finish_time)
		mins  = cls.get_mins(start_time, finish_time)
		total_hours = '{}.{}'.format(hours, mins)
		return float(total_hours)

	@classmethod
	def get_total_weekly_hours(cls, job_details):
		return int(cls.get_sum(job_details,'total_hours').split('.')[0])
		
class ProcessJobForm(BaseHandler):

	def __init__(self, request, response):
		self.initialize(request, response)
		self._day_dict = {'mon':'Monday','tue':'Tuesday','wed':'Wednesday',
		                  'thu':'Thursday','fri':'Friday','sat':'Saturday','sun':'Sunday'}
		
	def get(self):
		self.fill_form()
		
	def post(self):

		# get the details entered by the user
		date = self.request.get('date')
		week_day = self.request.get('dayOfWeek')
		title = self.request.get('title')
		descr = self.request.get('description')
		loc   = self.request.get('Location')
		start_time  = self.request.get('startTime')
		finish_time = self.request.get('finishTime')
		hourly_rate = self.request.get('hourRate')
		hours = self.request.get('hours')
		additional_payment = self.request.get('addPayment')


		self.process(date, week_day, title, descr, 
			         loc, start_time, finish_time, 
			         hourly_rate, additional_payment) # process the user's information

	def validate_day(self, day):
		'''validate_day(str) -> return(val)
		Return False if the user enters and incorrect weekday name else returns
		the the actually day entered by the user.
		'''
		if day:
		   day = day[:3].lower() 
		   return day in self._day_dict and self._day_dict[day]
		   
	# fill in the form with the user details
	def fill_form(self, date='', week_day='', title='', descr='', loc='',
		          startTime='', finishTime='', hours='', payment='',
		          hourRate='', error='', error_week='', 
		          start_time='', finish_time='', msg=''):

		self.render('job_details_entry_form.html', date=date, dayOfWeek=week_day, title=title, 
			        description=descr, Location=loc, startTime=startTime, finishTime=finishTime,
			        hourRate=hourRate, hours=hours, paymemnt=payment, error=error,
			        error_week=error_week, date_error=date, startTimeError=start_time, 
			        finishTimeError=finish_time, msg=msg, user=USERNAME)

	def make_job_details_dict(self, date, day):
		"""make_job_details_dict(str, str) -> return(dict)
		Creates a dictionary obj to be used for adding the job details
		"""
		week = {}
		week[date] = {day: {'Job_details':{}}}
		return week

	# adds details regarding the job
	def add_job_details(self, curr_job_dict, title, desc, location, 
		                start_time, finish_time, rate=0, 
					    total_hours=0, weekly_payment=0, date='', 
					    week_day='', additional_payment=0):

			Job_details = {'Job_title':str(title), 'Job_desc':str(desc), 
			               'location':str(location),'start_time':str(start_time), 
			               'finish_time':str(finish_time), 'hourly_rate':str(rate), 
			                'total_hours':str(total_hours), 'weekly_payment':str(weekly_payment),
			                'additional_payment':str(additional_payment)}

			curr_job_dict[date][str(week_day)]['Job_details'].update(Job_details) # update the current job dictionary with the new one

	# Update the job records
	def update_records(self, current_details=False, new_details=False, 
		               date=False, month_name=False, month=False, new=False,
		               month_update=False):
		
		year, month = get_month_and_year(date)

		# create a dictionary to hold the new year records
		# add new details to the newly created year dictionary
		if new:
			new_year = {year: {translate_month(month):{'week_date':{date:None}}}} 
			new_year[year][translate_month(month)]['week_date'][date] = new_details[date] 
			return new_year
			
		elif month_update:

			# Since there are only 4 weeks in a month
			# ensure that the each month only has a total of 4 weeks
			dates = current_details[year][month_name]['week_date'].keys()
			if len(dates) != 4:
				current_details[year][month_name]['week_date'].update(new_details)
				return True
		else:
			current_details[year][translate_month(month)]['week_date'][date].update(new_details[date])
						
	def process(self, date, week_day, title, descr, loc, start_time, finish_time, hourly_rate, additional_payment):

		# validate whether the details entered by the user is correct
		if week_day and self.validate_day(week_day) and date and loc \
		    and start_time and finish_time and hourly_rate and additional_payment != None: 

			user_db_obj = Cache.search() # get the user database files
			form_values = date, week_day, title, descr, loc, start_time, finish_time, hourly_rate
			hours = Calculate.get_total_hours(start_time, finish_time)
			payment = Calculate.get_daily_pay(hours, hourly_rate) # calculate the daily payment for the day
			week_day, date = self._day_dict[str(week_day[:3].lower())], str(date)
			work_info = self.make_job_details_dict(date, week_day) # create a dictionary to hold the job details for the year
			year, month  = get_month_and_year(date)
							
			# add the details of the job such as title, description, location, start time, etc to
			# the dictionary for the week commencing on that date
			self.add_job_details(work_info, title, descr, loc, start_time, 
							     finish_time, hourly_rate, hours, payment,
							     date, week_day, additional_payment) 

			if user_db_obj:
				job_details = ast.literal_eval(user_db_obj.JobDetails_details)
				print form_values

				try:
					dates  = job_details[year][translate_month(month)]['week_date'].keys() # get all dates for that month entry
					week_commencing = find_pos(dates, date) # find the position of specific date in question from the date keys
				except KeyError:
					week_commencing = None
	
				# if pos is not None add a new day work record to the same work week
				if week_commencing != None:
					self.update_records(current_details=job_details, new_details=work_info, date=date) # update the entries for the table using the date entered
					print '[+] Updated the details for the week commencing {}!!'.format(date)
					self.done(job_details=job_details, obj=user_db_obj, form_values=form_values)

				else:

					# find the month
					try:
						months  = job_details[year].keys() # retreive the months for that year: return as a list
						month_pos = find_pos(months, translate_month(month)) # find the position of the specific   
						                                                           #  month in question from the month keys
					except KeyError:
						month_pos = None

					# updates the month by adding a new week to that month
					if month_pos != None:
						# check it the month was successful updated
						succ = self.update_records(job_details, new_details=work_info, 
							                       month_name=months[month_pos], date=date,
							                       month_update=True)

						# check it the month was successful updated
						if succ:
							self.done(job_details=job_details, obj=user_db_obj, form_values=form_values)
						else:
							self.fill_form(msg='Failed to add week to given month, you have already have 4 weeks to that month')

					# add a new work month to the database
					elif month_pos == None:
						new_entry = self.update_records(current_details=job_details,
						                                new_details=work_info, 
						                                month=month, 
						                                date=date, 
						                                new=True)
						try:
							job_details[year].update(new_entry[year])  # update the year work dictionary with the new work month job details
							self.done(job_details=job_details, obj=user_db_obj, form_values=form_values) # update the database
						except KeyError:
							
							# add a new year to database along with the work details
							work_info = self.update_records(new_details=work_info, date=date, new=True)
							job_details.update(work_info)
							self.done(job_details=job_details, obj=user_db_obj, form_values=form_values)
					
			else:
				work_info = self.update_records(new_details=work_info, date=date, new=True)
				print '[+] New entry job table created for week commencing {}.'.format(date)
				self.done(job_details=work_info, add=True, form_values=form_values) # create a new job table
				
		else:
			# draw this form if the user details are incorrect
			self.fill_form(date, week_day, title, descr, loc, 
				           hourRate=hourly_rate, 
				           msg='Check if additional payment is None if so add 0')

		# add year to the table
	def done(self, job_details=False, obj=False, add=False, form_values=None):
		"""done(obj, str) -> returns(None)
		Adds or update the job details to database 
		"""

		# add the form values to the form so the user does not type the information again
		date, week_day, title, descr, loc, start_time, finish_time, hourly_rate = form_values #
		# if add is true adds a new row to the database
		# if add is False updates the selected row with the new data
		if add:
			JobDetailsDb.add(job_details)
		else:
			JobDetailsDb.update(obj, job_details)

		sleep(0.1)
		# add some animation here
		self.fill_form(date, week_day, title, descr,
		               loc, start_time, finish_time, 
		               hourly_rate, 
		               msg='The database has been successful update!!')
	
class VerificationHandler(object):

	USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
	PASSWD  = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
	EMAIL   = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

	@classmethod
	def valid_username(cls, username):
		"""validates the username"""
		return cls.USER_RE.match(username)

	@classmethod
	def valid_passwd(cls, password):
		"""validates the password"""
		return cls.PASSWD.match(password)

	@classmethod
	def valid_email(cls, email):
		"""validates the email"""
		return cls.EMAIL.match(email)

class Security(object):

	@classmethod
	def get_salt(cls):
		letter = list(letters)

		# shuffle the letters 3 times
		for i in xrange(3):
			shuffle(letter)
		return sha512(''.join(letter)).hexdigest()

	@classmethod
	def _hash_password(cls, name, password, secret):
		'''to be use in conjunction with password'''
		return hmac.new(str(name + password + secret)).hexdigest() # use sha256

	@classmethod
	def hash_str(cls, string):
		'''Takes a string and hash the string'''
		return hmac.new(str(string), SECRET).hexdigest()

	@classmethod
	def make_secure_str(cls, string):
		return '{}|{}'.format(string, cls.hash_str(string))
	
	@classmethod
	def _salt_password(cls, name, password, salt=None):
		if not salt:
			salt = cls.get_salt()
			return salt + "|" + cls._hash_password(name, password, SECRET)
		return salt + "|" + cls._hash_password(name, password, SECRET) 

	@classmethod
	def encrypt(cls, name, password, salt=None):
		return cls._salt_password(name, password, salt)

# change this to check

class LogOut(Cookies):

	def get(self):
		self.log_out()

	def log_out(self):
		self.delete_my_cookie()
		global USERNAME
		USERNAME = None
		self.redirect('/login')

class LoginPage(Cookies):
	
	def get(self):
		self.render('/login.html')

	def post(self):
		user_name   = self.request.get('name')
		user_passwd = self.request.get('password')

		if (user_name and user_passwd) and \
		     VerificationHandler.valid_username(user_name) and \
		     VerificationHandler.valid_passwd(user_passwd):

		     user_name = user_name.title()
		     usr_obj  = UsersDetailsDb.search(user_name)
		     if not usr_obj:
		     	self.render('/login.html', error='The password and username is invalid')
		     else:

			     password = usr_obj.password
			     salt = password.split('|')[0]
			     if password == Security.encrypt(user_name, user_passwd, salt):
			     	self.set_my_cookie(self.make_cookie(usr_obj))
			     	global USERNAME 
			     	USERNAME = user_name
			     	self.redirect('/JobDetails')
			     else:
			     	self.render('/login.html', name=user_name, error='The password is incorrect')

			     
		else:
			msg  = 'Invalid name'
			msg2 = 'Invalid password'
			self.render('/login.html', name_error=msg, passwd_error=msg2)

class Payment(Cookies):

	def get(self):

		if self.user_cookie:
			self.render('/payment.html')
		else:
			self.redirect('/login.html')

class Error(BaseHandler):

	def get(self):
		self.render('/no_page.html', user=USERNAME, msg='Oops nothing here to see')

class Records(Cookies):

	def get(self):
		if self.user_cookie:
			self.render('/history.html', user=USERNAME)
		else:
			self.redirect('/login')

	def post(self):

		start_date  = self.request.get('week_date')
		year, month = get_month_and_year(start_date)
		self.get_week_job_time_table(start_date, year, month)
	
	def get_week_job_time_table(self, start_date, year, month):
		"""get the records for any week"""

		if start_date:
			start_date = str(start_date)
			jb_obj = Cache.search() # change so that it uses a cache
			if not jb_obj:
				self.redirect('/no_page')
			else:
				job_dict = ast.literal_eval(jb_obj.JobDetails_details)

				try:
					job_details = job_dict[year][translate_month(month)]['week_date'][start_date]
				except KeyError:
					self.redirect('/no_page')
				else:
					days = order_by_days(job_details.keys()) # get the keys that represent the days
					total_payment = Calculate.get_weekly_payment(job_details)
					additional_payment = Calculate.get_additionl_payment(job_details)
					total = float(additional_payment) + float(total_payment)
					

					self.render('/job_timetable.html', 
						        days=days, 
						        date=start_date, 
						        job_details=job_details,
						        total=total_payment, 
						        total_hours=Calculate.get_total_weekly_hours(job_details),
						        additional_payment=total,
						        user=USERNAME,
						        time =jb_obj.created.strftime("%b %d, %Y"))


		
app = webapp2.WSGIApplication([('/addpayment|PAYMENT|Payment', Payment),
								('/new|Week|week', NewWeek),
								('/JobDetails|Details|details', ProcessJobForm),
								('/records', Records),
								('/login', LoginPage),
								('/logout', LogOut),
								('/signup', SignUp),
								('/faq', FAQ),
								('/no_page', Error),
							    ])


