# 🚀 User Management System – FastAPI
A production-ready **User Management System** built using **FastAPI**, implementing secure user registration, login, JWT authentication, role-based access control, password reset, profile management, account deactivation, and optional email verification.

This repository follows a **modular FastAPI architecture** for scalability, clarity, and maintainability.

---

## 📌 Features

### 🔐 Authentication & Security
- User registration with input validation  
- Secure password hashing using **bcrypt**  
- Login via **JWT tokens**  
- Middleware-based protected routes  
- Role-based access control (Admin/User)  

### 👤 User Operations
- Get user profile  
- Update profile  
- Deactivate account  
- Search users *(optional)*  
- Pagination *(optional)*  

### ✉️ Email Workflows
- Password reset via email 
- Optional email verification 

### 🧱 Clean Architecture
- Modular code structure  
- Separated models, schemas, routes, authentication modules  
- Environment variables support  
- Database-ready structure


---

## 🛠 Tech Stack
| Component | Technology |
|----------|------------|
| Framework | FastAPI |
| Language | Python |
| Database | MySQL + SQLAlchemy |
| Authentication | JWT |
| Hashing | bcrypt |
| Email | SMTP / FastAPI-Mail |
| Server | Uvicorn |

---

## 🔧 Installation & Setup

### 1️⃣ Clone the Repository
git clone https://github.com/iam-anilsolanki/User_Management_System-FastAPI.git 


### 🧪 Create Virtual Environment
python -m venv venv
source venv/bin/activate        # macOS/Linux
venv\Scripts\activate           # Windows

### 📄 Install All Dependencies
pip install -r final_app/requirements.txt

### 🚀 Run The Server 
uvicorn final_app.main:app --reload

