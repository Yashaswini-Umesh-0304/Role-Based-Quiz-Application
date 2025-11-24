import os
from flask import Flask,request, render_template, flash, redirect, url_for,session, logging, send_file
from flask_mysqldb import MySQL 
from wtforms import Form, StringField, TextAreaField, PasswordField, validators, DateTimeField, BooleanField, IntegerField
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired, FileAllowed
from functools import wraps
from werkzeug.utils import secure_filename
from datetime import timedelta, datetime
from flask import render_template_string
import functools
import math, random 
import json
import csv
import smtplib
import re
from wtforms_components import TimeField
from wtforms.fields.html5 import DateField
from wtforms.validators import ValidationError
from io import StringIO
from io import BytesIO

app = Flask(__name__)

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PORT'] = 3306
app.config['MYSQL_PASSWORD'] = 'YOUR_DB_PASSWORD'
app.config['MYSQL_DB'] = 'quizapp'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
app.config['ENV'] = 'development'

app.secret_key= 'ca2'

sender = 'youremailsender@abc.com'

mysql = MySQL(app)

@app.before_request
def make_session_permanent():
	session.permanent = True
	app.permanent_session_lifetime = timedelta(minutes=10)

def is_logged(f):
	@wraps(f)
	def wrap(*args, **kwargs):
		if 'logged_in' in session:
			return f(*args, **kwargs)
		else:
			flash('Session expired, please login.','danger')
			return redirect(url_for('login'))
	return wrap

@app.route('/')
def index():
	return render_template('index.html')

@app.route('/contact', methods=['GET','POST'])
def contact():
	if request.method == 'POST':
		careEmail = "youremail@gmail.com"
		cname = request.form['cname']
		cemail = request.form['cemail']
		cquery = request.form['cquery']
		if app.config['ENV'] != 'development':
			msgtocc = " ".join(["NAME:", cname, "EMAIL:", cemail, "QUERY:", cquery]) 
			server1 = smtplib.SMTP('smtp.stackmail.com',587)
			server1.ehlo()
			server1.starttls()
			server1.ehlo()
			server1.login('youremail.com', 'password')
			server1.sendmail(sender,cemail,"YOUR QUERY WILL BE PROCESSED!")
			msgtocc = " ".join(["NME:", cname, "EMAIL:", cemail, "QUERY:", cquery]) 
			server1.sendmail(sender, careEmail, msgtocc)
			server1.quit()
		flash('Your query has been recorded.', 'success')
		if 'logged_in' in session and session['logged_in']:
			return redirect(url_for('dashboard'))
		else:
			return redirect(url_for('index'))
	return render_template('contact.html')

@app.route('/lostpassword', methods=['GET','POST'])
def lostpassword():
	if request.method == 'POST':
		lpemail = request.form['lpemail']
		session['seslpemail'] = lpemail
		cur = mysql.connection.cursor()
		results = cur.execute('SELECT * from users where email = %s' , [lpemail])
		if results > 0:
			if app.config['ENV'] != 'development':
				server = smtplib.SMTP('smtp.stackmail.com',587)
				server.ehlo()
				server.starttls()
				server.ehlo()
				server.login('youremail@gmail.com', 'password')
				sesOTPfp = generateOTP()
				session['tempOTPfp'] = sesOTPfp
				session['seslpemail'] = lpemail
				server.sendmail(sender, lpemail, "Your OTP Verfication code for reset password is "+sesOTPfp+".")
				server.quit()
			return redirect(url_for('verifyOTPfp')) 
		else:
			return render_template('lostpassword.html',error="Account not found.")
	return render_template('lostpassword.html')

@app.route('/verifyOTPfp', methods=['GET','POST'])
def verifyOTPfp():
	if request.method == 'POST':
		fpOTP = request.form['fpotp']
		if 'tempOTPfp' in session:
			fpsOTP = session['tempOTPfp']
		else:
			# If not found in session, set a default OTP for local development testing
			fpsOTP = '12345'
		if(fpOTP == fpsOTP or app.config.get('ENV') == 'development'):
			session['seslpemail'] = session.get('seslpemail', '')
			return redirect(url_for('lpnewpwd')) 
	return render_template('verifyOTPfp.html')

@app.route('/lpnewpwd', methods=['GET','POST'])
def lpnewpwd():
	if request.method == 'POST':
		npwd = request.form.get('npwd')  # Use get to avoid errors if the key doesn't exist
		cpwd = request.form.get('cpwd')
		if 'seslpemail' in session:
			slpemail = session['seslpemail']
		else:
			return render_template('login.html', error="Session expired or invalid, please restart the process.")
		print(f"Attempting to update password for email: {slpemail}")
		if(npwd == cpwd):
			cur = mysql.connection.cursor()
			print(f"Querying database for email: '{slpemail}'")
			cur.execute("SELECT * FROM users WHERE email = %s", [slpemail])
			user_data = cur.fetchone()
			if user_data:
				print("Account found, updating password...")
				current_password = user_data['password']
				print(f"Current password in DB for {slpemail}: {current_password}")
				cur.execute("UPDATE users SET password = %s WHERE email = %s", [npwd, slpemail])
				mysql.connection.commit()
				cur.execute("SELECT * FROM users WHERE email = %s", [slpemail])
				updated_data = cur.fetchone()
				updated_password = updated_data['password']
				print(f"Password after update in DB: {updated_password}")
				if updated_password == npwd:
					print("Password update successful.")
					flash("Your password was successfully changed. Please log in.", 'success')
					session.pop('seslpemail', None)
					cur.close()
					return redirect(url_for('login'))
				else:
					print("Password was not updated properly.")
					return render_template('lpnewpwd.html', error="There was an issue updating your password.")
			else:
				print(f"Account not found with email: {slpemail}")
				cur.close()
				return render_template('login.html', error="Account not found. Please try again.")
		else:
			return render_template('lpnewpwd.html',error="Password doesn't match.")
	return render_template('lpnewpwd.html')

@app.route('/changepassword')
@is_logged
def changepassword():
	return render_template('changepassword.html')

def generateOTP() : 
    digits = "0123456789"
    OTP = "" 
    for i in range(5) : 
        OTP += digits[math.floor(random.random() * 10)] 
    return OTP 

@app.route('/register', methods=['GET','POST'])
def register():
	if request.method == 'POST':
		name = request.form['name']
		email = request.form['email']
		username = request.form['username']
		password = request.form['password']
		cpassword = request.form['cpassword']
		if not all([name, email, username]):
			return render_template('register.html', error="Data is missing or session expired. Please try again.")
		if(password == cpassword):
			session['tempName'] = name
			session['tempEmail'] = email
			session['tempUsername'] = username
			session['tempPassword'] = password
			session.modified = True  # Ensure session is marked as modified
			print("Session after registration:", dict(session))  # Debug: print session data
			if app.config['ENV'] != 'development':
				server = smtplib.SMTP('smtp.stackmail.com',587)
				server.ehlo()
				server.starttls()
				server.ehlo()
				server.login('yoursender@gmail.com', 'password')
				sesOTP = generateOTP()
				session['tempOTP'] = sesOTP
				server.sendmail(sender, email, "Your OTP Verfication code is "+sesOTP+".")
				server.quit()
			print("Session before redirect to verifyEmail:", dict(session))
			return redirect(url_for('verifyEmail')) 
		else:
			return render_template('register.html', error="Password does not match.")
	return render_template('register.html')

@app.route('/login', methods=['GET','POST'])
def login():
	if request.method == 'POST':
		username = request.form['username']
		password_candidate = request.form['password']
		cur = mysql.connection.cursor()
		results = cur.execute('SELECT * from users where username = %s' , [username])
		if results > 0:
			data = cur.fetchone()
			password = data['password']
			confirmed = data['confirmed']
			name = data['name']
			if confirmed == 0:
				error = 'Please confirm email before logging in.'
				return render_template('login.html', error=error)
			if confirmed == 1 and password == password_candidate:
				session['logged_in'] = True
				session['username'] = username
				session['name'] = name
				return redirect(url_for('dashboard'))
			else:
				error = 'Invalid password'
				return render_template('login.html', error=error)
			cur.close()
		else:
			error = 'Username not found'
			return render_template('login.html', error=error)
	return render_template('login.html')

@app.route('/verifyEmail', methods=['GET','POST'])
def verifyEmail():
	if request.method == 'POST':
		theOTP = request.form.get('eotp')
		mOTP = session.get('tempOTP')
		dbName = session.get('tempName')
		dbEmail = session.get('tempEmail')
		dbUsername = session.get('tempUsername')
		dbPassword = session.get('tempPassword')
		if(theOTP == mOTP or app.config.get('ENV') == 'development'):
			cur = mysql.connection.cursor()
			cur.execute('INSERT INTO users(username,name,email, password,confirmed) values(%s,%s,%s,%s,1)', (dbUsername, dbName, dbEmail, dbPassword))
			mysql.connection.commit()
			cur.close()
			session.clear()
			flash('You have successfully registered. Please log in to access your account.','success')
			return redirect(url_for('login'))
		else:
			return render_template('register.html',error="OTP is incorrect.")
	return render_template('verifyEmail.html')

@app.route('/changepassword', methods=["GET", "POST"])
def changePassword():
	if request.method == "POST":
		oldPassword = request.form['oldpassword']
		newPassword = request.form['newpassword']
		cur = mysql.connection.cursor()
		results = cur.execute("SELECT * from users where username = '" + session['username'] + "'")
		if results > 0:
			data = cur.fetchone()
			password = data['password']
			if(password == oldPassword):
				cur.execute("UPDATE users SET password = %s WHERE username = %s", [newPassword,session['username']])
				mysql.connection.commit()
				msg="Password changed successfully."
				flash('Password changed successfully.', 'success')
				cur.close()
				return render_template("dashboard.html", success=msg)
			else:
				error = "Old password entered is wrong."
				return render_template("changepassword.html", error=error)
		else:
			return render_template("changepassword.html")

def teacher_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Get the logged-in user's username from the session
        username = session.get("username")
        if username:
            # Query the database to check if the user is a teacher
            cur = mysql.connection.cursor()
            cur.execute("SELECT 1 FROM teachers WHERE username = %s", (username,))
            is_teacher = cur.fetchone()
            
            if is_teacher:
                # Proceed if the user is a teacher
                return f(*args, **kwargs)
            else:
                # If the user is not a teacher, check if they are in the students table
                cur.execute("SELECT 1 FROM students WHERE username = %s", (username,))
                is_student = cur.fetchone()
                
                if not is_student:
                    # If neither a teacher nor a student, allow access without restriction
                    return f(*args, **kwargs)
                
                # If the user is a student, deny access to the teacher's section
                flash("Students are not allowed access to the teacher's section.", "error")
                return redirect(url_for("dashboard"))  # Redirect to dashboard
        else:
            flash("You need to log in to access this page.", "error")
            return redirect(url_for("login"))
    return decorated_function

@app.route('/dashboard')
@is_logged
def dashboard():
	return render_template('dashboard.html')

@app.route('/logout')
def logout():
	session.clear()
	flash('Successfully logged out', 'success')
	return redirect(url_for('index'))

class UploadForm(FlaskForm):
	subject = StringField('Subject')
	topic = StringField('Topic')
	doc = FileField('CSV Upload', validators=[FileRequired()])
	start_date = DateField('Start Date')
	start_time = TimeField('Start Time', default=datetime.utcnow()+timedelta(hours=5.5))
	end_date = DateField('End Date')
	end_time = TimeField('End Time', default=datetime.utcnow()+timedelta(hours=5.5))
	password = StringField('Test Password', [validators.Length(min=3, max=6)])

	def validate_end_date(form, field):
		if field.data < form.start_date.data:
			raise ValidationError("End date must not be earlier than start date.")
	
	def validate_end_time(form, field):
		start_date_time = datetime.strptime(str(form.start_date.data) + " " + str(form.start_time.data),"%Y-%m-%d %H:%M:%S").strftime("%Y-%m-%d %H:%M")
		end_date_time = datetime.strptime(str(form.end_date.data) + " " + str(field.data),"%Y-%m-%d %H:%M:%S").strftime("%Y-%m-%d %H:%M")
		if start_date_time >= end_date_time:
			raise ValidationError("End date time must not be earlier/equal than start date time")
	
	def validate_start_date(form, field):
		if datetime.strptime(str(form.start_date.data) + " " + str(form.start_time.data),"%Y-%m-%d %H:%M:%S") < datetime.now():
			raise ValidationError("Start date and time must not be earlier than current")

class TestForm(Form):
	test_id = StringField('Test ID')
	password = PasswordField('Test Password')

def generate_simple_test_id():
	# Debug print to confirm the function is being called
	print("Generating simple test id...")
	# Fetch all test_ids from the teachers table
	cur = mysql.connection.cursor()
	cur.execute('SELECT test_id FROM teachers')
	result = cur.fetchall()
	cur.close()
	print(f"Type of 'result': {type(result)}")
	print(f"Fetched result: {result}")
	if isinstance(result, tuple) and all(isinstance(row, dict) for row in result):
		test_ids = [row.get('test_id', '') for row in result]
	numeric_test_ids = []
	for test_id in test_ids:
		match = re.match(r'QZ(\d+)', test_id)
		if match:
			numeric_test_ids.append(int(match.group(1)))  # Extract the number part of the test_id
	if numeric_test_ids:
		new_test_number = max(numeric_test_ids) + 1
	# Generate the new test_id in the format QZ<number>
	new_test_id = f'QZ{new_test_number}'
	print(f"Generated new test id: {new_test_id}")
	return new_test_id

@app.route('/create-test', methods = ['GET', 'POST'])
@teacher_required
@is_logged
def create_test():
	form = UploadForm()
	if request.method == 'POST' and form.validate_on_submit():
		f = form.doc.data
		filename = secure_filename(f.filename)
		f.save('questions/' + filename)
		print("Calling generate_simple_test_id...") 
		test_id = generate_simple_test_id()
		with open('questions/' + filename) as csvfile:
			reader = csv.DictReader(csvfile, delimiter = ',')
			cur = mysql.connection.cursor()
			for row in reader:
				cur.execute('INSERT INTO questions(test_id,qid,q,a,b,c,d,ans,marks) values(%s,%s,%s,%s,%s,%s,%s,%s,%s)', (test_id, row['qid'], row['q'], row['a'], row['b'], row['c'], row['d'], row['ans'], 1 ))
			cur.connection.commit()
			start_date = form.start_date.data
			end_date = form.end_date.data
			start_time = form.start_time.data
			end_time = form.end_time.data
			start_date_time = str(start_date) + " " + str(start_time)
			end_date_time = str(end_date) + " " + str(end_time)
			password = form.password.data
			subject = form.subject.data
			topic = form.topic.data
			cur.execute('INSERT INTO teachers (username, test_id, start, end, password, subject, topic) values(%s,%s,%s,%s,%s,%s,%s)',
			(dict(session)['username'], test_id, start_date_time, end_date_time, password, subject, topic))
			cur.connection.commit()
			cur.close()
			flash(f'Test ID: {test_id}', 'success')
			return redirect(url_for('dashboard'))
	return render_template('create_test.html' , form = form)

@app.route('/deltidlist', methods=['GET'])
@teacher_required
@is_logged
def deltidlist():
	cur = mysql.connection.cursor()
	results = cur.execute('SELECT test_id from teachers where username = %s', [session['username']])
	if results > 0:
		cresults = cur.fetchall()
		cur.close()
		return render_template("deltidlist.html", cresults = cresults)
	else:
		flash("No test found.", "error")
		return redirect(url_for("dashboard"))  # Ensure redirect or proper message

@app.route('/deldispques', methods=['GET','POST'])
@is_logged
def deldispques():
	if request.method == 'POST':
		tidoption = request.form['choosetid']
		cur = mysql.connection.cursor()
		cur.execute('SELECT * from questions where test_id = %s', [tidoption])
		callresults = cur.fetchall()
		cur.close()
		return render_template("deldispques.html", callresults = callresults)

@app.route('/<testid>/<qid>')
@is_logged
def del_qid(testid, qid):
	cur = mysql.connection.cursor()
	results = cur.execute('DELETE FROM questions where test_id = %s and qid =%s', (testid,qid))
	mysql.connection.commit()
	if results>0:
		flash('Deleted successfully.', 'success')
		cur.execute('SELECT * FROM questions WHERE test_id = %s', [testid])
		updated_questions = cur.fetchall()
		cur.close()
		return render_template("deldispques.html", callresults=updated_questions, success="Deleted successfully")
	else:
		return redirect(url_for('dashboard'))

@app.route('/updatetidlist', methods=['GET'])
@teacher_required
@is_logged
def updatetidlist():
	cur = mysql.connection.cursor()
	results = cur.execute('SELECT test_id from teachers where username = %s', [session['username']])
	if results > 0:
		cresults = cur.fetchall()
		cur.close()
		return render_template("updatetidlist.html", cresults = cresults)
	else:
		flash("No test found.", "error")
		return redirect(url_for("dashboard"))  # Ensure redirect or proper message

@app.route('/updatedispques', methods=['GET','POST'])
@is_logged
def updatedispques():
	if request.method == 'POST':
		tidoption = request.form['choosetid']
		cur = mysql.connection.cursor()
		cur.execute('SELECT * from questions where test_id = %s', [tidoption])
		callresults = cur.fetchall()
		cur.close()
		return render_template("updatedispques.html", callresults = callresults)

@app.route('/update/<testid>/<qid>', methods=['GET','POST'])
@is_logged
def update_quiz(testid, qid):
	if request.method == 'GET':
		cur = mysql.connection.cursor()
		cur.execute('SELECT * FROM questions where test_id = %s and qid =%s', (testid,qid))
		uresults = cur.fetchall()
		mysql.connection.commit()
		return render_template("updateQuestions.html", uresults=uresults)
	if request.method == 'POST':
		ques = request.form['ques']
		ao = request.form['ao']
		bo = request.form['bo']
		co = request.form['co']
		do = request.form['do']
		anso = request.form['anso']
		cur = mysql.connection.cursor()
		cur.execute('UPDATE questions SET q = %s, a = %s, b = %s, c = %s, d = %s, ans = %s where test_id = %s and qid = %s', (ques,ao,bo,co,do,anso,testid,qid))
		cur.connection.commit()
		flash('Updated successfully.', 'success')
		cur.execute('SELECT * FROM questions WHERE test_id = %s', [testid])
		updated_questions = cur.fetchall()
		cur.close()
		return render_template("updatedispques.html", callresults=updated_questions, success="Updated successfully")
	else:
		msg="ERROR  OCCURED."
		flash('ERROR  OCCURED.', 'error')
		return redirect(url_for('updatedispques', error=msg))

@app.route('/viewquestions', methods=['GET'])
@teacher_required
@is_logged
def viewquestions():
	cur = mysql.connection.cursor()
	results = cur.execute('SELECT test_id from teachers where username = %s', [session['username']])
	if results > 0:
		cresults = cur.fetchall()
		cur.close()
		return render_template("viewquestions.html", cresults = cresults)
	else:
		flash("No test found.", "error")
		return redirect(url_for("dashboard"))  # Ensure redirect or proper message

@app.route('/displayquestions', methods=['GET','POST'])
@is_logged
def displayquestions():
	if request.method == 'POST':
		tidoption = request.form['choosetid']
		cur = mysql.connection.cursor()
		cur.execute('SELECT * from questions where test_id = %s', [tidoption])
		callresults = cur.fetchall()
		cur.close()
		return render_template("displayquestions.html", callresults = callresults)

@app.route('/give-test/<testid>', methods=['GET','POST'])
@is_logged
def test(testid):
	print(f"Accessing test page for test ID: {testid}")  # Debug
	if request.method == 'GET':
		print("Rendering test page")
		cur = mysql.connection.cursor()
		results = cur.execute('SELECT * from questions where test_id = %s',[testid])
		results = cur.fetchall()
		cur.close()
		cur = mysql.connection.cursor()
		results2 = cur.execute('SELECT end from teachers where test_id = %s',[testid])
		results2 = cur.fetchall()
		cur.close()
		return render_template("testquiz.html", callresults = results, callresults2 = results2)
	if request.method == 'POST':
		print("Test submitted by user")
		cur = mysql.connection.cursor()
		results1 = cur.execute('SELECT COUNT(qid) from questions where test_id = %s',[testid])
		results1 = cur.fetchone()
		cur.close()
		completed=1
		for sa in range(1,results1['COUNT(qid)']+1):
			answerByStudent = request.form[str(sa)]
			if not answerByStudent:
				flash('You must answer all questions before submitting.', 'error')
				return redirect(url_for('test', testid=testid))  # Reload the test page
			cur = mysql.connection.cursor()
			cur.execute('INSERT INTO students values(%s,%s,%s,%s)', (session['username'], testid, sa, answerByStudent))
			mysql.connection.commit()
		cur.execute('INSERT INTO studentTestInfo values(%s,%s,%s)', (session['username'], testid, completed))
		mysql.connection.commit()
		cur.close()
		flash('Test submitted successfully. You can view your results.', 'success')
		print("Flash message triggered.")
		return redirect(url_for('dashboard'))

@app.route("/give-test", methods = ['GET', 'POST'])
@is_logged
def give_test():
	global duration, marked_ans	
	form = TestForm(request.form)
	if request.method == 'POST' and form.validate():
		test_id = form.test_id.data
		password_candidate = form.password.data
		cur = mysql.connection.cursor()
		results = cur.execute('SELECT * from teachers where test_id = %s', [test_id])
		if results > 0:
			data = cur.fetchone()
			password = data['password']
			start = data['start']
			start = str(start)
			end = data['end']
			end = str(end)
			if password == password_candidate:
				now = datetime.now()
				now = now.strftime("%Y-%m-%d %H:%M:%S")
				now = datetime.strptime(now,"%Y-%m-%d %H:%M:%S")
				if datetime.strptime(start,"%Y-%m-%d %H:%M:%S") < now and datetime.strptime(end,"%Y-%m-%d %H:%M:%S") > now:
					results = cur.execute('SELECT completed from studentTestInfo where username = %s and test_id = %s', (session['username'], test_id))
					if results > 0:
						results = cur.fetchone()
						is_completed = results['completed']
						if is_completed == 0:
							return redirect(url_for('test' , testid = test_id))
						else:
							flash('Test already given', 'success')
							return redirect(url_for('give_test'))
				else:
					if datetime.strptime(start,"%Y-%m-%d %H:%M:%S") > now:
						flash(f'Test start time is {start}', 'danger')
					else:
						flash(f'Test has ended', 'danger')
					return redirect(url_for('give_test'))
				return redirect(url_for('test' , testid = test_id))
			else:
				flash('Invalid password', 'danger')
				return redirect(url_for('give_test'))
		flash('Invalid testid', 'danger')
		return redirect(url_for('give_test'))
		cur.close()
	return render_template('give_test.html', form = form)

def totmarks(username,tests): 
	cur = mysql.connection.cursor()
	for test in tests:
		testid = test['test_id']
		results = cur.execute("select sum(marks) as totalmks from students s,questions q \
			where s.username=%s and s.test_id=%s and s.qid=q.qid and s.test_id=q.test_id \
			and s.ans=q.ans", (username, testid))				
		results = cur.fetchone()
		if str(results['totalmks']) == 'None':
			results['totalmks'] = 0
		test['marks'] = results['totalmks']
		if "Decimal" not in str(results['totalmks']): 
			mstr = str(results['totalmks']).replace('Decimal', '')
			results['totalmks'] = mstr
			test['marks'] = results['totalmks']
	return tests

def marks_calc(username,testid):
	print(f"Entering marks_calc for {username} and test {testid}")  # Debug print
	cur = mysql.connection.cursor()
	results = cur.execute("select sum(marks) as totalmks from students s,questions q \
			where s.username=%s and s.test_id=%s and s.qid=q.qid and s.test_id=q.test_id \
			and s.ans=q.ans", (username, testid))
	results = cur.fetchone()
	cur.close()
	print(f"Results for {username}, Test {testid}: {results}")  # Debugging line
	if results is None or results['totalmks'] is None:
		total_marks = 0
	else:
		total_marks = results['totalmks']
	return total_marks
		
@app.route('/<username>/tests-given')
@is_logged
def tests_given(username):
	if username == session['username']:
		cur = mysql.connection.cursor()
		results = cur.execute('select distinct(students.test_id),subject,topic from students,teachers where students.username = %s and students.test_id=teachers.test_id', [username])
		results = cur.fetchall()
		results = totmarks(username,results)
		return render_template('tests_given.html', tests=results)
	else:
		flash('You are not authorized', 'danger')
		return redirect(url_for('dashboard'))

@app.route('/download-results/<testid>', methods=['GET'])
@is_logged
def download_results(testid):
    cur = mysql.connection.cursor()

    # Fetch student test results for the given test ID
    results = cur.execute(
        'SELECT users.name AS name, users.username AS username, test_id '
        'FROM studentTestInfo, users '
        'WHERE test_id = %s AND completed = 1 AND studentTestInfo.username = users.username',
        [testid]
    )

    # Fetch results
    results = cur.fetchall()

    # Debug: Print the raw results to ensure we are fetching data
    print(f"Raw Results: {results}")

    if not results:
        # Return 404 if no results are found for the given test ID
        return "No results found for this test ID", 404

    # Prepare results data
    final = []
    for idx, student in enumerate(results, start=1):
        # Calculate the marks for each student
        marks = marks_calc(student['username'], testid)
        # Append data in the final list
        final.append([idx, student['name'], marks])

    # Debug: Print the final list to check if data is correctly formatted
    print(f"Formatted Final Data: {final}")

    # Create CSV dynamically in memory
    si = StringIO()
    writer = csv.writer(si)
    writer.writerow(['Sr No', 'Name', 'Marks'])  # Write CSV header
    writer.writerows(final)  # Write CSV data

    # Reset the pointer of StringIO to the start
    si.seek(0)

    # Convert the StringIO content to bytes
    output = si.getvalue().encode('utf-8')  # Convert string to bytes

    # Debug: Ensure that the CSV content is correct
    print(f"CSV Content: {si.getvalue()}")

    # Send the CSV as a downloadable file
    return send_file(
        BytesIO(output),  # Send the byte data
        as_attachment=True,
        attachment_filename=f"{testid}_results.csv",  # Use 'attachment_filename' for older Flask versions
        mimetype='text/csv'
    )

@app.route('/<username>/tests-created/<testid>', methods = ['GET'])
@is_logged
def student_results(username, testid):
	if username == session['username']:
		cur = mysql.connection.cursor()
		results = cur.execute('select users.name as name,users.username as username,test_id from studentTestInfo,users where test_id = %s and completed = 1 and studentTestInfo.username=users.username ', [testid])
		results = cur.fetchall()
		print(f"Students fetched: {results}") 
		final = []
		for idx, student in enumerate(results, start=1):
			print(f"Calculating marks for: {student['username']}, Test ID: {testid}")
			marks = marks_calc(student['username'], testid)
			print(f"Marks for {student['username']}: {marks}")  # Debug print
			final.append([idx, student['name'], marks])
		return render_template('student_results.html', data=final, testid=testid)

@app.route('/<username>/tests-created')
@teacher_required
@is_logged
def tests_created(username):
	if username == session['username']:
		cur = mysql.connection.cursor()
		results = cur.execute('select * from teachers where username = %s', [username])
		results = cur.fetchall()
		return render_template('tests_created.html', tests=results)
	else:
		flash('You are not authorized', 'danger')
		return redirect(url_for('dashboard'))

if __name__ == "__main__":
	app.run(debug=True, host='127.0.0.1', port=5000)
