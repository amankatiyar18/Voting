from enum import Enum
import logging
import os
import datetime
from typing import Dict, List, Optional, Set
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.staticfiles import StaticFiles
from sqlalchemy import func
from sqlalchemy.exc import SQLAlchemyError
from jose import JWTError
from starlette.middleware.base import BaseHTTPMiddleware
from pydantic import BaseModel
from sqlalchemy.orm import sessionmaker, Session
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from starlette.responses import JSONResponse
from fastapi.openapi.utils import get_openapi
from fastapi.encoders import jsonable_encoder
import jwt
from models import (
    CandidateModel,
    ConstituencyModel,
    ResultModel,
    RoleModel,
    UserModel,
    VoteModel,
    get_engine,
)
from fastapi.middleware.cors import CORSMiddleware


app = FastAPI()

origins = [
    "http://localhost:3000",
    "http://localhost:5173", 
    "http://127.0.0.1:8000",  
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"], 
    allow_headers=["*"],  
)

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
SECRET_KEY = os.getenv("SECRET")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15

blacklist: Set[str] = set()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except ValueError:
        return False

def create_access_token(data: dict, expires_delta: Optional[datetime.timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.datetime.utcnow() + expires_delta
    else:
        expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def decode_access_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return True, payload
    except jwt.PyJWTError:
        return False, JSONResponse(status_code=400, content={"data":"Token expired"})

class UserLogin(BaseModel):
    username: str
    password: str

class UserCreate(BaseModel):
    username: str
    password: str
    constituency_id: int

class UserUpdate(BaseModel):
    username: Optional[str] = None
    constituency_id: Optional[int] = None

class User(BaseModel):
    id: int
    username: str
    hashed_password: str
    constituency_id: int
    status: bool

    class Config:
        from_attributes = True

class RoleCreate(BaseModel):
    role_name: str
    permissions: Optional[str] = None
    exceptions: Optional[str] = None
    restricted: Optional[bool] = False

class Role(BaseModel):
    id: int
    role_name: str
    permissions: str
    created_at: datetime.datetime
    updated_at: datetime.datetime

class ConstituencyCreate(BaseModel):
    name: str

class Constituency(BaseModel):
    id: int
    name: str
    created_at: datetime.datetime
    updated_at: datetime.datetime

class PositionEnum(str, Enum):
    MLA = 'MLA'
    MP = 'MP'

class CandidateCreate(BaseModel):
    constituency_id: int
    result_id: int

class Candidate(BaseModel):
    id: int
    constituency_id: int
    result_id: int
    created_at: datetime.datetime
    updated_at: datetime.datetime

class VoteCreate(BaseModel):
    user_id: int
    candidate_id: int
    result_id: int

class Vote(BaseModel):
    id: int  
    user_id: int
    candidate_id: int
    result_id: int
    created_at: datetime.datetime
    updated_at: datetime.datetime

    class Config:
        from_attributes = True

class VoteResponseModel(BaseModel):
    id: Optional[int]
    user_id: Optional[int]
    candidate_id: Optional[int]
    result_id: Optional[int]
    constituency_id: Optional[int]

class Token(BaseModel):
    access_token: str
    token_type: str
    is_admin: bool

class Result(BaseModel):
    id: int
    name: str
    created_at: datetime.datetime
    updated_at: datetime.datetime
    position: PositionEnum

    class Config:
        from_attributes = True

class ResultCreate(BaseModel):
    name: str
    position: PositionEnum
    constituency_id: int

class RoleAssignment(BaseModel):
    user_id: int
    role_id: int

def assign_role(user_id: int, role_id: int):
    engine = get_engine()
    Session = sessionmaker(bind=engine)
    
    try:
        with Session() as session:
            user = session.query(UserModel).filter(UserModel.id == user_id).first()
            role = session.query(RoleModel).filter(RoleModel.id == role_id).first()

            if not user:
                return False, "User not found"
            if not role:
                return False, "Role not found"

            user.role_id = role_id            
            session.commit()            
            user_info = {
                'id': user.id,
                'username': user.username,
                'role_id': user.role_id,
            }

            return True, user_info

    except SQLAlchemyError as e:
        session.rollback()
        return False, f"An error occurred while updating the record: {str(e)}"

def save_vote(data):
    engine = get_engine()
    Session = sessionmaker(bind=engine)
    
    with Session() as session:
        try:
            user = session.query(UserModel).filter(UserModel.id == data.get('user_id')).first()
            candidate = session.query(CandidateModel).filter(CandidateModel.id == data.get('candidate_id')).first()

            if not user:
                return False, "User not found"
            if not candidate:
                return False, "Candidate not found"

            if user.constituency_id != candidate.constituency_id:
                return False, "User can only vote for candidates in their constituency"

            result_id = data.get('result_id')
            if not result_id:
                return False, "Result ID is required"

            existing_vote = session.query(VoteModel).filter_by(
                user_id=user.id,
                result_id=result_id
            ).first()

            if existing_vote:
                return False, "User has already voted"

            vote_record = session.query(VoteModel).filter_by(
                user_id=user.id,
                candidate_id=candidate.id,
                result_id=result_id
            ).first()

            if vote_record:
                vote_record.total_votes += 1
            else:
                vote_record = VoteModel(
                    user_id=user.id,
                    candidate_id=candidate.id,
                    result_id=result_id,
                    constituency_id=candidate.constituency_id
                )
                session.add(vote_record)

            session.commit()

            vote_data = {
                'id': vote_record.id,
                'user_id': vote_record.user_id,
                'candidate_id': vote_record.candidate_id,
                'result_id': vote_record.result_id,
                'constituency_id': vote_record.constituency_id,  
                'created_at': vote_record.created_at,
                'updated_at': vote_record.updated_at
            }

            return True, vote_data

        except SQLAlchemyError as e:
            session.rollback()
            return False, f"An error occurred while creating the vote record: {e}"

def verify_token(request: Request):
    token = request.headers.get("Authorization")
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token missing")
    
    token = token.replace("Bearer ", "")
    if token in blacklist:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token invalidated")
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

class RBACMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        token = request.cookies.get("access-token")

        if not token:
            authorization: str = request.headers.get("Authorization")
            if authorization and authorization.startswith("Bearer "):
                token = authorization[len("Bearer "):]

        request.state.token = token  

        endpoint_path = request.url.path.strip("/")
        http_method = request.method.lower()

        if endpoint_path in ("token", "logout", "favicon.ico", "openapi.json", "docs", "To-view-all-api", "users", "constituencies"):
            return await call_next(request)

        if not token:
            return JSONResponse(status_code=401, content={"detail": "Not authenticated"})

        try:
            status, payload = decode_access_token(token)
            if not status:
                return payload

            user_id = payload.get("user_id")

            engine = get_engine()
            Session = sessionmaker(bind=engine)
            with Session() as session:
                user = session.query(UserModel).filter(UserModel.id == user_id).first()
                if not user:
                    return JSONResponse(status_code=403, content={"detail": "User not found"})

                if user.is_admin:
                    return await call_next(request)

                role = session.query(RoleModel).filter(RoleModel.id == user.role_id).first()
                if not role:
                    return JSONResponse(status_code=403, content={"detail": "Role not found"})

                permissions = set(role.permissions.split(",")) if role.permissions else set()
                exceptions = set(role.exceptions.split(",")) if role.exceptions else set()

                required_permission = f"{http_method}:{endpoint_path}"

                if required_permission in exceptions:
                    return JSONResponse(status_code=403, content={"detail": "You don't have access"})

                if required_permission not in permissions:
                    return JSONResponse(status_code=403, content={"detail": "Permission denied"})

                return await call_next(request)
        except Exception as e:
            return JSONResponse(status_code=500, content={"detail": f"An error occurred: {str(e)}"})

app.add_middleware(RBACMiddleware)

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def authenticate_user(username: str, password: str):
    engine = get_engine()
    SessionLocal = sessionmaker(bind=engine)

    session = SessionLocal()
    try:
        user = session.query(UserModel).filter(UserModel.username == username).first()
        if not user or not verify_password(password, user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return user
    except Exception as e:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during authentication"
        )
    finally:
        session.close()

@app.post("/token", response_model=Token)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    token_data = {
        "sub": user.username,
        "user_id": user.id,
        "roles": user.role_id,
        "is_admin": user.is_admin  
    }
    access_token = create_access_token(data=token_data, expires_delta=datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    response = JSONResponse(content={"access_token": access_token, "token_type": "bearer"})
    response.set_cookie(key="access-token", value=access_token, httponly=True, secure=True, samesite='Lax')
    return response

@app.post("/logout")
async def logout(request: Request):
    token = request.state.token  

    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    if token in blacklist:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Token already invalidated")
    
    try:
        jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    blacklist.add(token)
    return {"message": "Successfully logged out"}

@app.get("/protected")
def protected_route(request: Request, token_payload: dict = Depends(verify_token)):
    return {"message": "You have access to this route", "user": token_payload["sub"]}

@app.post("/users", response_model=User, tags=["Users"])
def create_user_endpoint(user: UserCreate, token_payload: Dict = Depends(verify_token)):
    hashed_password = hash_password(user.password)
    user_data = user.dict()
    user_data['hashed_password'] = hashed_password
    del user_data['password']
    
    success, result = UserModel.create_record(user_data)
    
    if success:
        return result
    else:
        raise HTTPException(status_code=500, detail=result)

@app.get("/To-view-all-api")
def get_custom_openapi():
    openapi_schema = get_openapi(
        title="Voting-System",
        description="Making voting simple",
        version="1.0.0",
        routes=app.routes,
    )
    return JSONResponse(content=openapi_schema)

@app.get("/users", tags=["Users"])
def read_all_users(id: Optional[int] = None, username: Optional[str] = None, constituency: Optional[str] = None, status: Optional[bool] = None):
    filters = {"id": id, "username": username, "constituency": constituency, "status": status}
    filters = {k: v for k, v in filters.items() if v is not None}

    status, data = UserModel.get_all(filters)
    if status:
        return {"data": data}
    return {"msg": data}

@app.put("/users/{user_id}", tags=["Users"])
def update_user_endpoint(user_id: int, user_updates: UserUpdate, token_payload: Dict = Depends(verify_token)):
    updates = user_updates.dict(exclude_unset=True)
    status, data = UserModel.update(user_id, updates)
    if status:
        return {"data": data}
    return {"msg": data}

@app.delete("/users/{user_id}", tags=["Users"])
def delete_user(user_id: int, token_payload: Dict = Depends(verify_token)):
    status, data = UserModel.delete(user_id)
    if status:
        return {"data": data}
    return {"msg": data}
