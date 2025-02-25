
import re
import os
import gc
import json
import secrets
import random
import base64
import smtplib
import psycopg2
import numpy as np
import pandas as pd
from io import StringIO
from exception import *
from googleapiclient.errors import HttpError
from google.oauth2 import service_account
from googleapiclient.discovery import build
from sentence_transformers import SentenceTransformer
from deep_translator import GoogleTranslator
from flask import Flask,request,render_template,jsonify,flash,redirect,url_for,session

SERVICE_ACCOUNT_FILE = './token_cred.json'
# Define scopes for Google Drive API
SCOPES = ['https://www.googleapis.com/auth/drive','https://www.googleapis.com/auth/spreadsheets']
# Shared credentials for all users
credentials = service_account.Credentials.from_service_account_file(SERVICE_ACCOUNT_FILE, scopes=SCOPES)


app = Flask(__name__)
app.secret_key = secrets.token_hex(24)  # Required for flash messages

# Load a pre-trained embedding model
model = SentenceTransformer('all-MiniLM-L6-v2')

def get_files_from_google_drive():
    try:
        # Allowed file extensions
        allowed_extensions = ('.csv','.xlsx')
        # credentials = authenticate_and_list_files()
        # Build Google Drive API client
        service = build('drive', 'v3', credentials=credentials)
        FOLDER_ID = '1SNEOT6spU3wD7AVJI_w53bfMDig2Ss4l' 
        try:
            folder_metadata = service.files().get(fileId=FOLDER_ID, fields='id').execute()
        except HttpError as e:
            if e.resp.status == 404:
                raise FolderNotAvailable()
            else:
                raise e  # Re-raise other HttpError exceptions

        # Query files within the folder
        query = f"'{FOLDER_ID}' in parents"
        if service:
            files = []
            next_page_token = None
            # Paginate through the results
            while True:
                response = service.files().list(
                    q=query,
               
                    spaces='drive',
                    fields='nextPageToken, files(id, name)',
                    pageToken=next_page_token
                ).execute()

                files.extend(response.get('files', []))
                next_page_token = response.get('nextPageToken')
                if not next_page_token:
                    break
            # Print all files in the folder
            if files:
                files_with_id_dict = {}
                for file in files:
                    if file['name'].endswith(allowed_extensions):
                        files_with_id_dict[file['name']] = file['id']
                        print(f"File Name: {file['name']}, File ID: {file['id']}")
                print('file:',files_with_id_dict)
                # # Get the list of files with allowed extensions
                # files = [os.path.basename(f) for f in [key for key,val in files_with_id_dict.items() if key.endswith(allowed_extensions)]]

                return files_with_id_dict
            else:
                raise FolderNotAvailable()
    except FolderNotAvailable as exe:
        # flash('FolderNotAvailable','error')
        return jsonify({'error': str(exe)}), 404

def sql_connection():
    "Establish a PostgreSQL connection."
    
    connection_string = 'postgres://postgres:postgres@localhost:5432/postgres'
    connection = psycopg2.connect(connection_string)
    return connection

def load_excel_file_data(file_id):
    """Load data from the selected file based on its type (CSV, Excel, PDF)."""
    # try:
    # https://drive.google.com/file/d/1Xg6UiNRmAq4PPWqsholcdanQtae9RiDq/view?usp=drive_link

        # Dictionary mapping file names to Google Drive file IDs

    csv_url = f"https://drive.google.com/uc?id={file_id}"
  
    # Read the CSV file
    df = pd.read_excel(csv_url,engine='openpyxl')
    return df

def load_csv_file_data(file_id):
    """Load data from the selected file based on its type (CSV, Excel, PDF)."""
    # try:
    # https://drive.google.com/file/d/1Xg6UiNRmAq4PPWqsholcdanQtae9RiDq/view?usp=drive_link

        # Dictionary mapping file names to Google Drive file IDs

    csv_url = f"https://drive.google.com/uc?id={file_id}"
  
    # Read the CSV file
    df = pd.read_csv(csv_url)
    return df

def cosine_similarity(A, B):
    "find out similarity between two vector"
    dot_product = np.dot(A, B)
    magnitude_A = np.linalg.norm(A)
    magnitude_B = np.linalg.norm(B)
    
    if not magnitude_A or not magnitude_B:
        return 0  # Avoid division by zero
    
    return dot_product / (magnitude_A * magnitude_B)


def vector_search(vector1,vector2):
    "Find out similarity score."
    similarity = cosine_similarity(vector1, vector2)
    print('similarity_score::',similarity)
    return similarity


def insert_data_in_db(model,doc_id,file_name,table_name):
    
    pg_table = table_name.lower()
    # service = build('drive', 'v3', credentials=credentials)
    # # Get available CSV files from Google Drive
    # files_with_ids = get_files_from_google_drive()

    if file_name.split('.')[1] == 'csv':
        df = load_csv_file_data(doc_id)
    else:
        df = load_excel_file_data(doc_id)
    print('columns:::::',df.columns)
    que_lst = df['Question'].to_list()
    # Convert text to embeddings
    embeddings = model.encode(que_lst)
    
    # vectorstring conversation 
    str_embed = [str(i.tolist()) for i in embeddings]
    
    df['embedding'] = str_embed
    print('df:',df)
    #Convert DataFrame to CSV format (in-memory)
    csv_buffer = StringIO()
    df.to_csv(csv_buffer, index=False, header=False,sep='|')  # No index, no headers
    csv_buffer.seek(0)  # Move to start
    conn = sql_connection()
    cursor = conn.cursor()

    pg_table = table_name.lower()
    print(pg_table)
    # Copy CSV buffer into PostgreSQL table
    cursor.copy_from(csv_buffer, pg_table, sep='|', columns=['question','answer','embedding'])
    conn.commit()
    cursor.close()
    conn.close()
    return 0



def check_status_of_table_in_db(table_name):

    pg_table = table_name.lower()

    conn = sql_connection()
    cursor = conn.cursor()
    sql_query = f'''SELECT EXISTS (
                            SELECT FROM 
                                pg_tables
                            WHERE 
                                schemaname = 'public' AND 
                                tablename  = '{pg_table}'
                            );
                            '''
    cursor.execute(sql_query)
    result = cursor.fetchone()
    status = result[0]
    conn.close()
    return status

def create_table_in_db(table_name):
    conn = sql_connection()
    cursor = conn.cursor()

    cursor.execute(f'''CREATE TABLE IF NOT EXISTS {table_name} (question text,
                                                                answer text,
                                                                embedding vector(384) default NULL
                                                                )''')
    conn.commit()
    cursor.close()
    conn.close()
    return 0



def get_most_similar_question(model,doc_id,file_name , table_name, query_embedding, top_k=1):
    '''
    Retrieve the most similar question from the database using vector similarity.
    Args:
        query: The query question to compare.
        top_k: Number of similar results to retrieve.
    Returns:
        The most similar question from the database.
    '''
    # Convert embedding to a PostgreSQL-readable format
    lst_embedding = str(query_embedding.tolist())

    status = check_status_of_table_in_db(table_name)

    if status != True:
        create_table_in_db(table_name)
        result = insert_data_in_db(model,doc_id,file_name,table_name)
        print(result)
        if result == 1:
            raise TableNotExist()

    # SQL query to find the most similar question
    sql_query = f"""
    SELECT answer, embedding FROM {table_name}
    ORDER BY embedding <-> '{lst_embedding}' asc
    LIMIT {top_k};
    """
    print(sql_query)
    conn = sql_connection()
    cursor = conn.cursor()
    cursor.execute(sql_query)
    results = cursor.fetchall()
    conn.close()

    if results:
        answer =results[0][0]
        vector =  np.array(eval(results[0][1]))
        
        similarity_score = vector_search(query_embedding,vector)

        return similarity_score,results[0][0],answer # Return the first similar question
    
    return None

def get_answer(similar_vector,table_name):
    "when similarity score is > 0.89"

    # SQL query to find the most similar question
    sql_query = f"""
    SELECT answer FROM {table_name}
    ORDER BY embedding <-> '{similar_vector}'
    LIMIT 1;
    """
    conn = sql_connection()
    cursor = conn.cursor()
    cursor.execute(sql_query)
    results = cursor.fetchall()
    conn.close()

    if results:
        answer = results[0][0]
    return answer


def get_similar_questions(table_name,query_embedding):
    "Get similar question when have similarity score >0.4"

    lst_embedding = str(query_embedding.tolist())
        
    # SQL query to find the most similar question
    sql_query = f"""
    SELECT question,embedding FROM {table_name}
    ORDER BY embedding <-> '{lst_embedding}'
    LIMIT {5};
    """
    conn = sql_connection()
    cursor = conn.cursor()
    cursor.execute(sql_query)
    results = cursor.fetchall()
    conn.close()

    if results:
        similar_que_index_lst = [] 
        for i,j in enumerate(results):
            # Retrieve the most similar question from the database
            similar_vector = np.array(eval(j[1]))
            similarity_score = vector_search(query_embedding,similar_vector)

            if similarity_score>0.4:
                similar_que_index_lst.append(i)

        similar_question = ''
        for index in similar_que_index_lst:
            similar_question+=(results[index][0]+',\n')
    else:
        similar_question = ''
    return similar_question


def create_register_table(conn):
    try:
        sql_query = """ CREATE TABLE IF NOT EXISTS public.register_table
                        (
                            user_id serial PRIMARY KEY,
                            username varchar NOT NULL UNIQUE,
                            password bytea NOT NULL,
                            email_id character varying(255) NOT NULL UNIQUE
                        )
                    """
        curr = conn.cursor()
        curr.execute(sql_query)
        return 0
    except:
        return 'Table Not Created.'
    

def send_mail(receiver_email_id,message):
    try:
        sender_email_id = 'mayurnandanwar@ghcl.co.in'
        password = 'uvhr zbmk yeal ujhv'
        # creates SMTP session
        s = smtplib.SMTP('smtp.gmail.com', 587)
        # start TLS for security
        s.starttls()
        # Authentication
        s.login(sender_email_id, password)
        # message to be sent
        # sending the mail
        s.sendmail(sender_email_id, receiver_email_id, str(message))
        # terminating the session
        s.quit()

        del sender_email_id,password
        gc.collect()
        return 0
    except:
        return jsonify({'error':'The Message cannot be Sent.'})
    

def create_user_que_ans_table(curr,conn):
    sql_query = '''CREATE TABLE IF NOT EXISTS public.user_que_ans
                (
                    id serial PRIMARY KEY,
                    email_id varchar NOT NULL UNIQUE,
                    answer varchar,
                    feedback varchar
                )
                '''
    curr.execute(sql_query)
    return 0

@app.route('/')
def index():
    return render_template('login.html')


@app.route('/login', methods=['GET', 'POST'])
def login_page():
    try:
        if request.method == 'POST':
            email = request.form['email']
            password = request.form['password']
            
            print('email::',email)
            sql_query = f"select * from public.register_table where email_id = '{email}';"
            connection = sql_connection()
            if connection == 'Connection Error':
                raise PgConnectionError()
                
            else:
                curr = connection.cursor()
                curr.execute(sql_query)
                rows  = curr.fetchall()
                connection.close()

            if  len(rows) == 0 :
                flash("Email Id Not Found.", "error")

            if len(rows) != 0 :
                print('in')
                if rows[0][-1] != email :
                    flash("Invalid Email Id", "error")
                    return redirect(url_for('login_page'))
        
                decPassword = base64.b64decode(rows[0][-2]).decode("utf-8")
                print('decPassword::',decPassword)
                if password == decPassword:

                    session['email'] = email
                    return redirect(url_for('chatpage'))
                else:
                    flash("Invalid Password", "error")
                del [decPassword]
                gc.collect()
            del email,password,sql_query,rows
            gc.collect()
        return render_template('login.html')
    except PgConnectionError as exe:
        return jsonify({'error':str(exe)}),400


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    try:
        if request.method == 'POST':
            name = request.form['name']
            email = request.form['email']
            password = request.form['password']
            confirm_password = request.form['confirm_password']
            connection = sql_connection()
            table_create = create_register_table(connection)
            if table_create == 0:
                curr = connection.cursor()
                sql = f"SELECT email_id FROM public.register_table WHERE email_id = '{email}';"
                
                curr.execute(sql)
                rows = curr.fetchall()
                connection.close()
            else:
                raise PgConnectionError()
            
            if len(rows) == 0:
                # Check if passwords match
                if password != confirm_password:
                    flash("Passwords do not match!", "error")
                    return redirect(url_for('signup'))
                
                # Check password strength using regex
                password_pattern = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$')
                if not password_pattern.match(password):
                    flash("Password must contain at least 8 characters, including one uppercase letter, one lowercase letter, one digit, and one special character.", "error")
                    return redirect(url_for('signup'))
                
                # Generate a random token
                token = random.randint(100000, 999999)
                print('token:',token)
                # Store the token in the session for validation
                session['token'] = str(token)
                session['email'] = email
                # this required for adding pass and name after validation
                session['password'] = password
                session['name'] = name
                # Send the token via email
                subject = "Email Verification Code"
                body = f"Your verification code is {token}. Please enter it on the website to verify your email."
                message = f"Subject: {subject}\n\n{body}"
                msg = send_mail(email, message)

                if msg == 0:
                    flash("Code has been sent to register email id.", "info")
                    # Redirect to the validate_mail route with email as a parameter
                    return redirect(url_for('validate_mail', email=email))
                del password_pattern,token,subject,body,message,msg
                gc.collect()
            else:
                flash("Email Already Exist.", "info")
        return render_template('signup.html')
    except PgConnectionError as exe:
        return jsonify({"error": str(exe)})
    
@app.route('/chatpage', methods=['GET'])
def chatpage():
    """Render the homepage with a list of allowed files."""

    if 'email' not in session:  # Check if user is logged in
            flash('Please login to access the chat page.', 'warning')  # Flash the message
            return redirect(url_for('login_page'))  # Redirect to login page
    
    file_dicts = get_files_from_google_drive()
    # files = list(file_dicts.keys())
    return render_template('chatpage.html', files=file_dicts)

@app.route('/ask', methods=['POST','GET'])
def get_ans_from_csv():
    ''' this function is used to get answer from given csv.

    Args:
    doc_file([CSV]): comma separated file 
    query_text :  Question

    Returns: Answer
    '''

    if 'email' not in session:
        flash("Please log in to access this functionality.", "error")
        return redirect(url_for('login_page'))
    
    email = session['email']
    
    query_text = request.form.get("query_text")
    # selected_language = request.form.get("selected_language")
    # selected_language = 'en'
    doc_file = request.form.get('selected_file')
    print('doc_file:',doc_file)

    file_with_id_dict = get_files_from_google_drive()
    doc_id = file_with_id_dict[doc_file]

    if query_text :
        if not doc_file or doc_file == "Select a document":
            flash("Please select a document to proceed.")
            return redirect(url_for('chatpage'))
        else:
            model = SentenceTransformer('all-MiniLM-L6-v2')
            query_embedding = model.encode(query_text)

            table_name = doc_file.split('.')[0]
            # Retrieve the most similar question from the database
            similarity_score, similar_vector, ans = get_most_similar_question(model,doc_id, doc_file,table_name, query_embedding, top_k=1)

            if similarity_score >= 0.8:
                answer = ans
                # # Translate if needed
                # if selected_language != 'en':
                #     if selected_language in ['gu', 'hi', 'ta']:
                #         answer = GoogleTranslator(source='en', target=selected_language).translate(ans)
                # else:
                #     answer = ans

            elif 0.4 <= similarity_score < 0.8:
                similar_question = get_similar_questions(table_name, query_embedding)
                
                # Convert similar questions into a formatted response
                if similar_question:
                    question_part = "Similar questions found"
                    suggestions = [s.strip() for s in similar_question.split(',')]
                    links_html = '<br>'.join(f'<a href="#" class="query-link">{s}</a>' for s in suggestions)
                    answer = f'{question_part}:<br>{links_html}'
                else:
                    answer = "No similar questions found."
            else:
                answer = "Not Found."

            return jsonify({'answer': answer})
    else:
        return redirect(url_for('chatpage'))
    

@app.route('/validate_mail',methods=['POST','GET'])
def validate_mail():
    
    try:
        email = request.args.get('email')  # Retrieve email from query string
        
        if request.method == 'POST':
            entered_token = str(request.form['token'])

            # Compare the entered token with the session token
            if str(session.get('token')) == str(entered_token):
                password = session['password']
                name = session['name']
                encPassword = base64.b64encode(password.encode("utf-8"))
                connection = sql_connection()
                table_created = create_register_table(connection)
                if table_created==0:
                    sql_query = "INSERT INTO public.register_table (username, password, email_id) VALUES (%s, %s, %s);"
                    curr = connection.cursor()
                    curr.execute(sql_query, (name, encPassword, email))
                    connection.commit()
                    connection.close()
                else:
                    raise ConnectionError()

                #remove session after adding it to table 
                session.pop('password')
                session.pop('name')
                session.pop('token')

                flash("Signup successful! Please login.", "success")
                del password,name,encPassword,sql_query
                gc.collect()

                return redirect(url_for('login_page'))
            else:
                # return "Invalid token. Please try again.", 400
                flash("Invalid code. Please try again.", "error")  # Flash error message

        return render_template('validate_mail.html', email=email)
    
    except ConnectionError as exe:
        return jsonify({'error': str(exe)}),400
    
@app.route('/validate_mail_reset_password',methods=['POST','GET'])
def validate_mail_reset_password():
    email = request.args.get('email')  # Retrieve email from query string
    if request.method == 'POST':
        entered_token = str(request.form['token'])

        # Compare the entered token with the session token
        if str(session.get('reset_token')) == str(entered_token):
            return redirect(url_for('reset_password'))
        else:
            # return "Invalid token. Please try again.", 400
            flash("Invalid code. Please try again.", "error")  # Flash error message

    return render_template('reset_token_validate.html', email=email)


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password(): 
    try:
        if request.method == 'POST':
            email = session['email']
            new_password = request.form['new_password']
            confirm_password = request.form['confirm_password']
            password_pattern = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$')
            if not password_pattern.match(new_password):
                flash("Password must contain at least 8 characters, including one uppercase letter, one lowercase letter, one digit, and one special character.", "error")
                return render_template('reset_password.html')
        
            if new_password != confirm_password:
                flash("Passwords do not match.", "error")
                return render_template('reset_password.html')
            # Check password strength using regex
            else:
                encPassword = base64.b64encode(new_password.encode("utf-8"))
                sql_query = "UPDATE public.register_table SET password = %s WHERE email_id = %s;"
                connection = sql_connection()
                if connection == 'Connection Error':
                    raise PgConnectionError()
                else:
                    curr = connection.cursor()
                    curr.execute(sql_query,(encPassword,email))
                    connection.commit()
                    connection.close()

                    flash("Password has been reset successfully. You can now log in.", "success")
                del encPassword,sql_query
                gc.collect()
                return redirect(url_for('login_page'))
        return render_template('reset_password.html')
    except PgConnectionError as exe:
        return jsonify({'error':str(exe)})
    

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    try:
        if request.method == 'POST':
            email = request.form['email']
            session['email'] = email
            sql_query = f"SELECT * FROM public.register_table WHERE email_id = '{email}';"
            connection = sql_connection()
            if connection == 'Connection Error':
                raise PgConnectionError()
            else:
                curr = connection.cursor()
                curr.execute(sql_query)
                rows = curr.fetchall()
                connection.close()

            if len(rows) == 0:
                flash("Email not found. Please SignUp", "error")
                return redirect(url_for('signup'))
            else:
                # Generate a random token
                reset_token = str(random.randint(100000, 999999))
                session['reset_token'] = reset_token
                subject = "Code For Password Change"
                body = f"Your verification code is {reset_token}. Please enter it on the website to verify your email."
                message = f"Subject: {subject}\n\n{body}"
                msg = send_mail(email, message)
                
                del reset_token,subject,body,message
                gc.collect()

                if msg == 0:
                    flash("Code has been sent to registered email id.", "info")
                    return redirect(url_for('validate_mail_reset_password', email=email))
                
            del email,sql_query,rows
            gc.collect()
        return render_template('forgot_password.html')
    
    except PgConnectionError as exe:
        return jsonify({'error':str(exe)})


@app.route('/clear', methods=['POST'])
def clear():
    """Clear user feedback or session data."""
    # Any session or data clearing logic goes here (if needed)

    # Redirect to index function
    return redirect(url_for('chatpage'))
    # return render_template('chatpage.html')


@app.route('/save_feedback', methods=['POST'])
def save_feedback():
    """Save user feedback."""
    email = session.get('email')
    feedback_data = request.json  # Expecting JSON data

    if not email:
        return jsonify({'error': 'User not logged in'}), 401

    # Ensure file name is retrieved correctly
    file_name = feedback_data.get('selected_file')  # Extract correctly

    feedback_res = {}
    feedback_res['question'] = feedback_data['question']
    feedback_res['feedback'] = feedback_data['feedback']

    if not file_name:
        return jsonify({'error': 'File name is missing'}), 400

    print(f"Selected File: {file_name}")  # Debugging line

    # Fetch existing feedback
    sql_query = """SELECT feedback FROM public.user_feedback WHERE email_id = %s AND file_name = %s;"""
    
    with sql_connection() as conn:
        with conn.cursor() as curr:
            curr.execute(sql_query, (email, file_name))
            res = curr.fetchone()  # Fetch a single row

    if not res:
        # Insert new feedback
        feedback_json = json.dumps([feedback_res])  # Store as list
        sql_query = """INSERT INTO public.user_feedback (email_id, file_name, feedback) 
                       VALUES (%s, %s, %s);"""
        with sql_connection() as conn:
            with conn.cursor() as curr:
                curr.execute(sql_query, (email, file_name, feedback_json))
                conn.commit()
    else:
        # ans_lst = json.loads(res[0])  # Convert JSON string to Python list
        ans_lst = res[0]
        ans_lst.append(feedback_res)  # Append new feedback
        feedback_json = json.dumps(ans_lst)  # Convert back to JSON

        sql_query = """UPDATE public.user_feedback SET feedback = %s 
                       WHERE email_id = %s AND file_name = %s;"""
        with sql_connection() as conn:
            with conn.cursor() as curr:
                curr.execute(sql_query, (feedback_json, email, file_name))
                conn.commit()

    return jsonify({'message': 'Feedback saved successfully'}), 200


if __name__=='__main__':
    app.run(host='0.0.0.0',port=5010)




