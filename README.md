# Role-Based Quiz Application 🎓

A comprehensive, full-stack web-based examination system built with **Python (Flask)** and **MySQL**. This application features a robust **Role-Based Access Control (RBAC)** system, allowing distinct functionalities for Teachers (creating/managing quizzes) and Students (taking timed exams).

---

## 🚀 Features

### 👨‍🏫 Teacher Module
* **Secure Authentication:** Dedicated login and dashboard for instructors.
* **Test Management:** Create new quizzes with specific start/end dates and times.
* **Question Bank:**
  * **Bulk Upload:** Upload questions easily using CSV files.
  * **Management:** View, update, and delete questions directly from the dashboard.
* **Security:** Set unique passwords for each scheduled test to prevent unauthorized access.
* **Analytics:** View student attempts and download detailed result sheets in CSV format.

### 👨‍🎓 Student Module
* **Exam Dashboard:** View list of available and upcoming tests.
* **Secure Testing:** Access exams using a specific **Test ID** and **Password** provided by the instructor.
* **Timed Assessments:** Server-side validation ensures tests can only be taken within the scheduled window.
* **Instant Feedback:** Automated scoring provides immediate results upon submission.
* **History:** Track past performance and scores.

---

## 🛠️ Tech Stack

* **Backend:** Python 3, Flask Framework
* **Database:** MySQL (Relational Database)
* **Frontend:** HTML5, CSS3, JavaScript, Jinja2 Templates
* **Deployment:** Configured for Google App Engine (`app.yaml`)
* **Key Libraries:**
  * `Flask-MySQLdb`: For robust database connectivity.
  * `WTForms`: For secure form handling and validation.
  * `Pandas`: For handling CSV uploads and data processing.

---

## ⚙️ Setup & Installation

### Step 1: Clone the Project

```bash
git clone https://github.com/Yashaswini-Umesh-0304/Role-Based-Quiz-Application.git
```

### Step 2: Install Python Dependencies

Navigate to the project directory and install required packages:

```bash
cd Role-Based-Quiz-Application
pip install -r requirements.txt
```

### Step 3: Database Setup

#### 3.1 Create the Database

1. Open **MySQL Workbench**
2. Connect to your MySQL server
3. Execute the following query in the SQL editor:

```sql
CREATE DATABASE quizapp;
```

#### 3.2 Import the Database Schema

1. In MySQL Workbench, go to **Server > Data Import**
2. Select **Import from Self-Contained File**
3. Browse to the location of your `quizapp.sql` file and select it
4. Under **'Default Schema to be Imported To'**, select `quizapp` from the dropdown menu
5. Click **Start Import**
6. Wait for the import to complete

#### 3.3 Verify the Import

Execute the following queries to verify the database setup:

```sql
USE quizapp;

-- Verify table structure
DESCRIBE questions;
DESCRIBE users;
DESCRIBE teachers;
DESCRIBE students;
DESCRIBE studenttestinfo;

-- View data
SELECT * FROM users;
SELECT test_id FROM teachers;
```

### Step 4: Configure Database Connection

Open `app.py` and update the database configuration with your MySQL credentials:

```python
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'           # Your MySQL username
app.config['MYSQL_PORT'] = 3306
app.config['MYSQL_PASSWORD'] = 'YourPassword'  # Your MySQL password
app.config['MYSQL_DB'] = 'quizapp'
```

---

## 🚀 Running the Application

### Start the Flask Server

```bash
# Navigate to project directory
cd Role-Based-Quiz-Application

# Run the application
python app.py
```

---

## 📝 Usage Guide

### 👨‍🏫 Teacher Workflow

#### 1. Register & Login
* Navigate to the registration page
* Create a teacher account with your credentials
* Login to access the teacher dashboard

#### 2. Create a Quiz
1. From the dashboard, click on **Create Quiz**
2. Fill in the following details:
   - **Subject:** e.g., "Computer Science"
   - **Topic:** e.g., "Data Structures"
   - **Start Date & Time:** When the test becomes available
   - **End Date & Time:** When the test closes
   - **Test Password:** A secure password (3-6 characters)
3. **Upload CSV File:**
   - Click "Download Template" to get the CSV format
   - Prepare your questions in CSV format
   - Upload the CSV file

**CSV Format:**
```csv
qid,q,a,b,c,d,ans,marks
1,"What is 2+2?","3","4","5","6","b",1
2,"Capital of France?","Berlin","London","Paris","Rome","c",1
```

4. Click **Submit** to create the quiz
5. Note the generated **Test ID** (e.g., `QZ101`)

#### 3. Manage Questions
* **View Questions:** See all questions for your tests
* **Update Questions:** Edit question text or answer options
* **Delete Questions:** Remove specific questions from tests

#### 4. Monitor Results
1. Navigate to **Student Results** in the dashboard
2. Select a test to view student performance
3. Click **Download Results** to export scores as CSV

---

### 👨‍🎓 Student Workflow

#### 1. Register & Login
* Create a student account with your credentials
* Login to access the student dashboard

#### 2. Take a Quiz
1. Click on **Take Quiz** from the dashboard
2. Enter the **Test ID** provided by your teacher (e.g., `QZ101`)
3. Enter the **Test Password** shared by your teacher
4. Click **Start Test**

#### 3. Attempt the Exam
* The exam interface displays all the questions in the quiz
* Select your answers for all Multiple Choice Questions (MCQs)
* **Important:** Answer all questions before submitting
* Make sure to attend any quiz before it expires
* Click **Submit** when finished

#### 4. View Results
* Upon submission, your score is calculated and displayed instantly
* Navigate to **My Results** to view past test scores
* View detailed performance for each test

---
