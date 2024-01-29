import hashlib
import os
import re
import sqlite3
from datetime import datetime, timedelta
from typing import List

import jwt
from fastapi import FastAPI, HTTPException, status, Depends
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from pydantic import BaseModel

SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
DATABASE_PATH = 'database.db'
EMAIL_REGEX = """([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\\.[A-Z|a-z]{2,})+"""
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()


class Token(BaseModel):
    access_token: str
    token_type: str


class ErrorResponse(BaseModel):
    detail: str


class UserCreate(BaseModel):
    firstname: str = None
    lastname: str = None
    email: str = None
    password: str = None
    old_password: str = None

    def as_dict(self):
        return {
            "id": self.id,
            "firstname": self.firstname,
            "lastname": self.lastname,
            "email": self.email,
            "password": self.password,
        }

    class Config:
        from_attributes = True


class User(UserCreate):
    id: int

    class Config:
        from_attributes = True


# Function to get the current authenticated user
def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    user_data = fetch_one("SELECT * FROM users WHERE token=?", (token,))
    if user_data:
        return User(**user_data)
    else:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")


# Function to verify the provided password against the user's actual password
def verify_password(provided_password: str, actual_password: str) -> bool:
    print(f"{hash_password(provided_password)} = {actual_password}")
    return hash_password(provided_password) == str(actual_password)


# Function to update user data by ID in the database
def update_user_by_id(user_id: int, updated_data: dict) -> None:
    query = "UPDATE users SET firstname=?, lastname=?, email=?, password=? WHERE id=?"
    parameters = (updated_data.get("firstname"), updated_data.get("lastname"),
                  updated_data.get("email"), updated_data.get("password"), user_id)
    execute_query(query, parameters)


def hash_password(password):
    password_bytes = password.encode('utf-8')
    sha256_hash = hashlib.sha256()
    sha256_hash.update(password_bytes)
    hashed_password = sha256_hash.hexdigest()
    return hashed_password


def create_connection():
    return sqlite3.connect(DATABASE_PATH)


def execute_query(query, parameters=()):
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute(query, parameters)
    conn.commit()
    conn.close()


def fetch_one(query, parameters=()):
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute(query, parameters)
    result = cursor.fetchone()
    conn.close()

    # Convert the tuple to a dictionary
    if result:
        columns = [desc[0] for desc in cursor.description]
        result_dict = dict(zip(columns, result))
        return result_dict
    return None


def fetch_all(query, parameters=()):
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute(query, parameters)
    result = cursor.fetchall()
    conn.close()
    return result


def init_database():
    query = '''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                                               firstname TEXT, 
                                               lastname TEXT, 
                                               email TEXT, 
                                               password TEXT,
                                               token TEXT)'''
    execute_query(query)


def create_user(user: UserCreate):
    query = "INSERT INTO users (firstname, lastname, email, password) VALUES (?, ?, ?, ?)"
    parameters = (user.firstname, user.lastname, user.email, hash_password(user.password))
    execute_query(query, parameters)
    user_id = fetch_one("SELECT last_insert_rowid()")  # Retrieve the last inserted ID
    return user_id["last_insert_rowid()"] if user_id else None


def user_exists(email: str, user_id: int = None) -> bool:
    if user_id is None:
        query = "SELECT COUNT(*) FROM users WHERE email=?"
        result = fetch_one(query, (email,))
    else:
        query = "SELECT COUNT(*) FROM users WHERE email=? AND id != ?"
        result = fetch_one(query, (email, user_id))

    # Check if result is not None and 'COUNT(*)' key is present
    if result and 'COUNT(*)' in result:
        return result['COUNT(*)'] > 0
    else:
        return False


def get_all_users():
    query = "SELECT * FROM users"
    return fetch_all(query)


def get_user_by_id(user_id: int):
    query = "SELECT * FROM users WHERE id=?"
    user_data = fetch_one(query, (user_id,))

    if user_data:
        # Map the column names to the attribute names of the User class
        user_attributes = {"id": user_data["id"], "firstname": user_data["firstname"],
                           "lastname": user_data["lastname"],
                           "email": user_data["email"], "password": user_data["password"]}
        return User(**user_attributes)
    else:
        return None


# Authenticate user function
def authenticate_user(username: str, password: str):
    user_password = fetch_one("SELECT password FROM users WHERE email=?", (username,))
    user_data = fetch_one("SELECT * FROM users WHERE email=?", (username,))
    if user_data and verify_password(password, user_password["password"]):
        return {"id": user_data["id"], "firstname": user_data["firstname"], "lastname": user_data["lastname"],
                "email": user_data["email"], "password": user_data["password"]}
    return None


# Create access token function
def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# Store token in the database
def store_token(user_id: int, token: str):
    query = "UPDATE users SET token=? WHERE id=?"
    parameters = (token, user_id)
    execute_query(query, parameters)


if not os.path.exists(DATABASE_PATH):
    init_database()


@app.post("/token", response_model=Token)
async def post_login_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": form_data.username}, expires_delta=access_token_expires
    )

    # Store the token in the database
    store_token(user["id"], access_token)

    query = "SELECT * FROM users WHERE email=?"
    conn = create_connection()
    cursor = conn.cursor()

    # Pass the email as a parameter to the execute method
    cursor.execute(query, (form_data.username,))
    result = cursor.fetchone()

    conn.close()

    print(result)
    user_id = result
    print(form_data.username)
    print(user_id[0])

    return {"access_token": access_token, "token_type": "bearer", "user_id": user_id[0]}


@app.post("/register/", response_model=User, responses={
    201: {
        "description": "User Created",
        "model": User,
        "content": {"application/json": {"example": {
            "id": 1,
            "firstname": "John",
            "lastname": "Doe",
            "email": "john.doe@example.com",
            "password": "hashed_password"
        }}}
    },
    400: {
        "description": "Bad request",
        "model": ErrorResponse,
        "content": {"application/json": {"example": {"detail": "400 Email is already registered"}}}
    },
    422: {
        "description": "Missing Required Data",
        "model": ErrorResponse,
        "content": {"application/json": {"example": {"detail": "422 Email and password are required"}}}
    },
    500: {
        "description": "Internal Server Error",
        "model": ErrorResponse,
        "content": {"application/json": {"example": {"detail": "500 Internal server error"}}}
    }
})
def user_endpoint(user: UserCreate):
    # Validate input data
    if not user.email or not user.password:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                            detail="422 Email and password are required")

    # Continue validation
    if not user.firstname or not user.lastname:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                            detail="422 First name and last name are required")

    # Validate email
    if not re.fullmatch(EMAIL_REGEX, user.email):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="400 Invalid email")

    # Check if the email is already in use
    if user_exists(user.email):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="400 Email is already registered")

    if len(user.password) < 8:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="400 Password must be at least 8 characters long")

    try:
        user_id = create_user(user)
        response_data = {"id": user_id, **user.dict()}
        return JSONResponse(content=response_data, status_code=status.HTTP_201_CREATED)
    except sqlite3.Error:
        # Handle SQLite database errors
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail="500 Internal server error")
    except Exception as e:
        # Handle other unexpected errors
        # print(e)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail="500 Unexpected error occurred")


# GET request to retrieve all users or a specific user by ID
@app.get("/profile/", response_model=List[User], responses={
    200: {
        "description": "Successful Response",
        "model": List[User],
        "examples": {"users": [{"id": 1, "firstname": "John", "lastname": "Doe", "email": "john.doe@example.com",
                                "password": "d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35"}]}
    },
    404: {
        "description": "User Not Found",
        "model": ErrorResponse,
        "content": {"application/json": {"example": {"detail": "404 User not found"}}}
    }
})
async def get_users(user_id: int = None):
    if user_id is None:
        users = get_all_users()
        if not users:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="404 No users in database yet")
        formatted_users = [
            {"id": user[0], "firstname": user[1], "lastname": user[2], "email": user[3], "password": user[4]} for user
            in users
        ]
        return JSONResponse(content={"users": formatted_users}, status_code=status.HTTP_200_OK)

    user = get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="404 User not found")

    formatted_user = [{"id": user.id, "firstname": user.firstname, "lastname": user.lastname,
                       "email": user.email, "password": user.password}]

    return JSONResponse(content={"users": formatted_user})


@app.patch("/update/{user_id}", response_model=User, responses={
    200: {
        "description": "Successful Update",
        "model": User,
        "examples": {"user": {"id": 1, "firstname": "John", "lastname": "Doe", "email": "john.doe@example.com"}}
    },
    400: {
        "description": "Bad Request",
        "model": ErrorResponse,
        "content": {"application/json": {"example": {"detail": "400 Invalid input"}}}
    },
    401: {
        "description": "Unauthorized",
        "model": ErrorResponse,
        "content": {"application/json": {"example": {"detail": "401 Unauthorized"}}}
    },
    404: {
        "description": "User Not Found",
        "model": ErrorResponse,
        "content": {"application/json": {"example": {"detail": "404 User not found"}}}
    }
})
async def update_user(user_id: int, updated_data: UserCreate, current_user: User = Depends(get_current_user)):
    # Check if the user exists
    user = get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="404 User not found")

    # Check if the user_id in the URL matches the one in the form data
    # if user_id != int(updated_data.id):
    #     raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
    #                         detail="400 Mismatch between user_id in URL and form data")
    print(current_user.id)
    print(user_id)
    # Check if the authenticated user is the owner of the account
    if current_user.id != user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="401 Unauthorized")

    # Check if the email is already in use
    if user_exists(user.email, user_id):
        print(user.email)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="400 Email is already registered")

    # Validate the old password if a new password is provided
    if updated_data.password:
        if not updated_data.old_password:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="400 Invalid input. For a password change old_password must be provided."
            )
        if not verify_password(updated_data.old_password, hash_password(current_user.password)):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="400 Invalid input. Old password is required and must match the current password for "
                       "password change."
            )
    try:
        # Update user data
        updated_user_data = {k: v for k, v in updated_data.dict(exclude_unset=True).items()}
        update_user_by_id(user_id, updated_user_data)

        # Return the updated user data
        updated_user = get_user_by_id(user_id)
        if updated_user:
            return JSONResponse(content={"user": updated_user.as_dict()}, status_code=status.HTTP_200_OK)
        else:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="404 User not found")

    except Exception as e:
        print(e)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail="500 Internal server error")


# Endpoint to remove the account
@app.delete("/delete/me", response_model=dict, responses={
    200: {
        "description": "Account Removed",
        "content": {"application/json": {"example": {"detail": "Account removed successfully"}}}
    },
    401: {
        "description": "Unauthorized",
        "model": ErrorResponse,
        "content": {"application/json": {"example": {"detail": "401 Unauthorized"}}}
    },
    404: {
        "description": "User Not Found",
        "model": ErrorResponse,
        "content": {"application/json": {"example": {"detail": "404 User not found"}}}
    }
})
async def remove_account(current_user: User = Depends(get_current_user)):
    # Check if the user exists
    user = get_user_by_id(current_user.id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="404 User not found")

    # Check if the authenticated user is the owner of the account
    if current_user.id != user.id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="401 Unauthorized")

    try:
        # Remove the account
        query = "DELETE FROM users WHERE id=?"
        execute_query(query, (current_user.id,))
        return {"detail": "Account removed successfully"}
    except Exception as e:
        print(e)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail="500 Internal server error")


@app.get("/")
async def root():
    return {"message": "Hello World"}
