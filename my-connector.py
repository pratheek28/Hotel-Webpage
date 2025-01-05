import mysql.connector
import razorpay
from flask import Flask, render_template, request, url_for, redirect, jsonify, session, flash
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, verify_jwt_in_request, get_jwt_identity
from functools import wraps
from datetime import timedelta, datetime, date
import random
import smtplib
from email.message import EmailMessage
import re
from flask_cors import CORS

app = Flask(__name__)
CORS(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
app.secret_key = 'your_secret_key'
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=5)
app.config['SESSION_TYPE'] = 'filesystem'
client = razorpay.Client(auth=("rzp_test_key", "rzp_test_secret"))

mydb = mysql.connector.connect(
    host='localhost',
    user='root',
    passwd='Pratheek09!',
    port='3306',
    database='users'
)



global otp_attempts
global user_clearance
global bookCounter

bookCounter = -1
otp_attempts = 3
user_clearance = 'user'

mycursor = mydb.cursor()

def db_insert(id, email, password, first_name, last_name):
    dt = datetime.now()
    insert_query = '''INSERT INTO users (id, email, password, first_name, last_name, date_created, clearance) VALUES (%s, %s, %s, %s, %s, %s, %s)'''
    data = (id, email, password, first_name, last_name, dt, user_clearance)
    mycursor.execute(insert_query, data)
    mydb.commit()
    print('Success')

def jwt_required_custom(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        token = session.get('access_token', None)
        if token is None:
            return redirect('/login')  # REDIRECTS TO LOGIN IF NO TOKEN IS FOUND
        try:
            # Manually set the token in the request headers
            request.headers = {"Authorization": f"Bearer {token}"}
            verify_jwt_in_request()  # VERIFIES THAT THE TOKEN IS VALID
        except Exception as e:
            return redirect('/login')  # IF TOKEN IS NOT VALID IT REDIRECTS TO LOGIN
        return fn(*args, **kwargs)
    return wrapper

def otp_verify(user_otp, otp):
    if bcrypt.check_password_hash(otp, user_otp):
        return True
    else:
        return False

def check_email_provider(email):
    gmail_pattern = r'^[a-zA-Z0-9._%+-]+@gmail\.com$'
    outlook_pattern = r'^[a-zA-Z0-9._%+-]+@outlook\.com$'
    hotmail_pattern = r'^[a-zA-Z0-9._%+-]+@hotmail\.com$'

    if re.match(gmail_pattern, email):
        return True
    elif re.match(outlook_pattern, email):
        return True
    elif re.match(hotmail_pattern, email):
        return True
    else:
        return False

@app.route('/', methods=['GET', 'POST'])
def index():
    return render_template("welcome.html")

#RENDERS LOGIN TEMPLATE
@app.route('/login', methods=['GET', 'POST'])
def login():
    return render_template("login.html")

@app.route('/login-check', methods=['GET', 'POST'])
def login_check():
    user_email = str(request.form['email'])
    user_pass = str(request.form['password'])
    email_query = 'SELECT COUNT(email) FROM users WHERE email = %s'
    mycursor.execute(email_query, (user_email,))
    result_email = mycursor.fetchone()
    if result_email[0] != 1:
        return render_template("login.html", message="Email Not Found!")
    elif result_email[0] == 1:
        password_query = 'SELECT password FROM users WHERE email = %s'
        mycursor.execute(password_query, (user_email,))
        result_password = mycursor.fetchone()
        result = str(result_password[0])
        if bcrypt.check_password_hash(result, user_pass):
            access_token = create_access_token(identity=user_email)
            session['access_token'] = access_token
            clearance_query = 'SELECT clearance FROM users WHERE email = %s'
            mycursor.execute(clearance_query, (user_email,))
            result_clearance = mycursor.fetchone()
            session['clearance'] = str(result_clearance[0])
            id_query = 'SELECT id FROM users WHERE email = %s'
            mycursor.execute(id_query, (user_email,))
            result_id = mycursor.fetchone()
            session['id'] = result_id
            return redirect(url_for('website'))
        else:
            return render_template("login.html", message="Incorrect Password!")

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    return render_template("signup.html")

@app.route('/signup-check', methods=['GET', 'POST'])
def signup_check():
    global otp_attempts
    if request.method == "POST":
        id_index = 0
        user_email = str(request.form['email'])
        user_pass = str(request.form['password'])
        first_name = str(request.form['first_name'])
        last_name = str(request.form['last_name'])
        encrypted_pass = str(bcrypt.generate_password_hash(user_pass).decode('utf-8'))
        user_repass = request.form['re-password']
        valid_providor = check_email_provider(user_email)
        if valid_providor == False:
            return render_template('signup.html', message="We only accept emails from GMAIL, OUTLOOK, or HOTMAIL!", color='red')
        email_query = 'SELECT COUNT(email) FROM users WHERE email = %s'
        mycursor.execute(email_query, (user_email,))
        result_email = mycursor.fetchone()
        if result_email[0] == 1:
            return render_template('login.html', message="Email Already Exists! Log into your account here!", color="#228B22")

        if user_pass == user_repass:
            mycursor.execute("SELECT COUNT(id) FROM users WHERE id IS NOT NULL")
            result = mycursor.fetchone()
            count = result[0]
            if count == 0:
                id_index = id_index + 0
            else:
                id_index = count
            otp = ''
            for i in range(6):
                otp += str(random.randint(0, 9))

            print(otp)
            server = smtplib.SMTP('smtp.gmail.com', 587)
            server.starttls()

            from_mail = 'pratheek0928@gmail.com'
            server.login(from_mail, 'hxid bowh vqho krlh')

            msg = EmailMessage()
            msg['Subject'] = 'OTP Verification'
            msg['From'] = from_mail
            msg['To'] = user_email
            msg.set_content(f'Your OTP is: ' + otp + '. DO NOT SHARE THIS WITH ANYONE.')

            server.send_message(msg)

            encrypter_otp = str(bcrypt.generate_password_hash(otp).decode('utf-8'))
            otp_attempts = 3
            return render_template('otp_verify.html', email=user_email, password=encrypted_pass, index=id_index, correct_otp=encrypter_otp, source='signup', first_name=first_name, last_name=last_name)
        else:
            return render_template("signup.html", message="Passwords do not match!", color='red')

@app.route('/otp', methods=['GET', 'POST'])
def otp():
    global otp_attempts
    if request.method == "POST":
        source = str(request.form['hidden_source']) #CHECKS IF OTP IS BEING CALLED FOR SIGN UP
        if source == 'signup':
            user_otp = str(request.form['otp'])
            user_email = str(request.form['hidden_email'])
            user_password = str(request.form['hidden_password'])
            index = str(request.form['hidden_index'])
            correct_otp = str(request.form['hidden_correct_otp'])
            first_name = str(request.form['hidden_first_name'])
            last_name = str(request.form['hidden_last_name'])
            valid = False
            while valid == False and otp_attempts >= 1:
                valid = otp_verify(user_otp, correct_otp)
                if valid == False:
                    otp_attempts -= 1
                    if otp_attempts == 0: #CHECKS IF THE USER HAS ENTERED THE OTP INCORRECTLY 3 TIMES
                        return render_template('signup.html', message="You entered the wrong OTP 3 times! Re-enter your info for a new otp!")
                    else:
                        return render_template('otp_verify.html', email=user_email, password=user_password, index=index, correct_otp=correct_otp, source='signup', first_name=first_name, last_name=last_name, message="Incorrect! You have " + str(otp_attempts) + " remaining.")
                elif valid == True:
                    db_insert(index, user_email, user_password, first_name, last_name)
                    return render_template("login.html", message="Successfully registered your account! You may login here!")
        elif source == 'forgotpass': #CHECKS IF OTP IS BEING CALLED FOR RESETTING A FORGOTTEN PASSWORD
            user_otp = str(request.form['otp'])
            user_email = str(request.form['hidden_email'])
            correct_otp = str(request.form['hidden_correct_otp'])
            valid = False
            print(user_otp)
            print(correct_otp)
            while valid == False and otp_attempts >= 1:
                valid = otp_verify(user_otp, correct_otp)
                if valid == False:
                    otp_attempts -= 1
                    if otp_attempts == 0:
                        return render_template('forgotpass.html', message='You entered the wrong OTP 3 times! Re-enter your info for a new otp!')
                    else:
                        return render_template('otp_verify.html', email=user_email, correct_otp=correct_otp, source='forgotpass')
                elif valid == True:
                    return render_template('newpassword.html', email=user_email)

#RENDERS THE WEBPAGE TO RESET FORGOTTEN PASSWORD
@app.route('/render_forgotpass')
def render_forgot_pass():
    return render_template('forgotpass.html')

#ALLOWS USERS TO ENTER NEW PASSWORD AND SENDS AN OTP
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    global otp_attempts
    if request.method == "POST":
        user_email = str(request.form['email'])
        email_query = 'SELECT COUNT(email) FROM users WHERE email = %s'
        mycursor.execute(email_query, (user_email,))
        result_email = mycursor.fetchone()
        if result_email[0] != 1:
            return render_template('forgotpass.html', message="Email Not Found!")
        else:
            otp = ''
            for i in range(6):
                otp += str(random.randint(0, 9))

            print(otp)
            server = smtplib.SMTP('smtp.gmail.com', 587)
            server.starttls()

            from_mail = 'pratheek0928@gmail.com'
            server.login(from_mail, 'hxid bowh vqho krlh')

            msg = EmailMessage()
            msg['Subject'] = 'OTP Verification'
            msg['From'] = from_mail
            msg['To'] = user_email
            msg.set_content(f'Your OTP is: ' + otp + '. DO NOT SHARE THIS WITH ANYONE.')

            server.send_message(msg)

            encrypter_otp = str(bcrypt.generate_password_hash(otp).decode('utf-8'))
            print(encrypter_otp)
            otp_attempts = 3
            return render_template('otp_verify.html', source='forgotpass', email=user_email, correct_otp=encrypter_otp)

#UPDATES TO NEW PASSWORD
@app.route('/newpassword', methods=['GET', 'POST'])
def newpassword():
    if request.method == "POST":
        user_email = str(request.form['hidden_email'])
        password = str(request.form['newpass'])
        re_pass = str(request.form['reenterpass'])
        if password == re_pass:
            encrypt_pass = str(bcrypt.generate_password_hash(password).decode('utf-8'))
            dt = datetime.now()
            query = ('UPDATE users SET password = %s, date_modified = %s WHERE email = (%s)')
            mycursor.execute(query, (encrypt_pass, dt, user_email))
            mydb.commit()
            return render_template('login.html', message="Successfully updated your password! You may log into your account here!")
        else:
            return render_template('newpassword.html', message="Passwords do not match!")


@app.route('/render_roomCreator', methods=["GET", "POST"])
def renderRoomCreator():
    return render_template("roomcreator.html")

@app.route('/roomData', methods=['GET', 'POST'])
def roomData():
    if request.method == "POST":
        id_index = 0
        roomOccupancy = str(request.form['occupants'])
        roomNumber = str(request.form['roomNum'])
        roomRate = str(request.form['rate'])
        availability = "yes"

        mycursor.execute("SELECT COUNT(id) FROM rooms WHERE id IS NOT NULL")
        result = mycursor.fetchone()
        count = result[0]
        if count == 0:
            id_index = id_index + 0
        else:
            id_index = count
        dt = datetime.now()
        query = (
            "INSERT INTO rooms (id, roomNum, roomCapacity, roomRate, availability) "
            "VALUES (%s, %s, %s, %s, %s)"
        )
        mycursor.execute(query, (id_index, roomNumber, roomOccupancy, roomRate, availability))
        mydb.commit()

        return redirect('/website')


@app.route('/selectAvailableDates', methods=['GET', 'POST'])
def selectAvailableDates():
    room_id = request.form.get('room_id')
    session['selected_room'] = room_id
    mycursor.execute("SELECT start_date, end_date FROM reservations WHERE roomID = %s", (room_id,))
    bookings = mycursor.fetchall()

    columns = [desc[0] for desc in mycursor.description]
    bookings_dicts = [dict(zip(columns, booking)) for booking in bookings]

    unavailable_dates = set()
    for booking in bookings_dicts:
        start_date = booking['start_date']
        end_date = booking['end_date']
        current_date = start_date
        while current_date <= end_date:
            unavailable_dates.add(current_date)
            current_date += timedelta(days=1)

    sessionID = session['id']
    mycursor.execute("SELECT email, first_name, last_name FROM users WHERE id = %s", session['id'])
    result = mycursor.fetchall()
    resultList = list(result)
    email, firstName, lastName = resultList[0]
    return render_template('datepicker.html', room_id=room_id, email=email, firstName=firstName, lastName=lastName)


@app.route('/book_room', methods=['POST'])
def book_room():
    room_id = request.form.get('room_id')
    start_date = request.form.get('start_date')
    end_date = request.form.get('end_date')
    firstName = request.form.get('firstName')
    lastName = request.form.get('lastName')
    email = request.form.get('email')
    sessionID = session['id']

    # Fetch existing bookings for the room
    mycursor.execute("SELECT start_date, end_date FROM reservations WHERE roomID = %s", (room_id,))
    bookings = mycursor.fetchall()
    columns = [desc[0] for desc in mycursor.description]
    bookings_dicts = [dict(zip(columns, booking)) for booking in bookings]

    unavailable_dates = set()
    for booking in bookings_dicts:
        start_date_db = booking['start_date']
        end_date_db = booking['end_date']
        current_date = start_date_db
        while current_date <= end_date_db:
            unavailable_dates.add(current_date.strftime('%Y-%m-%d'))
            current_date += timedelta(days=1)

    # Check if the selected dates are unavailable
    selected_dates = set()
    current_date = date.fromisoformat(start_date)
    end_date = date.fromisoformat(end_date)
    while current_date <= end_date:
        selected_dates.add(current_date.isoformat())
        current_date += timedelta(days=1)

    # Debug statements
    print("Selected dates:", selected_dates)
    print("Unavailable dates:", unavailable_dates)

    # Clear previous flash messages
    session.pop('_flashes', None)

    # Check intersection and flash message if dates overlap
    if selected_dates.intersection(unavailable_dates):
        flash('One or more selected dates are unavailable. Please choose different dates.')
        return render_template('datepicker.html', room_id=room_id, email=email, firstName=firstName, lastName=lastName)

    # Proceed with booking if dates are available
    bookQuery = 'INSERT INTO reservations (roomID, userID, start_date, end_date, customerFirstName, customerLastName, customerEmail) VALUES (%s, %s, %s, %s, %s, %s, %s)'
    mycursor.execute(bookQuery, (room_id, sessionID[0], start_date, end_date, firstName, lastName, email))
    mydb.commit()
    return redirect('/website')



#THE WEBSITE
@app.route('/website')
@jwt_required_custom
def website():
    if session.get('clearance') == "admin": #THIS IS FOR ADMIN TO BE ABLE TO MAKE/CHANGE ROOMS
        # current_user = get_jwt_identity()
        # return f"Welcome to the website, {current_user}!"
        dataQuery = "SELECT * FROM rooms WHERE availability = %s"
        roomAvailability = "yes"
        mycursor.execute(dataQuery, (roomAvailability,))
        result = mycursor.fetchall()
        return render_template('website.html', data=result)
    elif session.get('clearance') == 'user': #FOR USERS
        return 'ape'

if __name__ == '__main__':
    app.run(debug=True)