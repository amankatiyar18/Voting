import enum
import os
from sqlite3 import IntegrityError
from typing import Optional
from dotenv import load_dotenv
from fastapi import Depends
from sqlalchemy import Column, DateTime, Enum as SQLEnum, Index, Integer, MetaData, String, Boolean, ForeignKey, create_engine, func
import sqlalchemy
from sqlalchemy.orm import sessionmaker, declarative_base, relationship
from passlib.context import CryptContext
import datetime
from datetime import datetime
load_dotenv()
from sqlalchemy.exc import SQLAlchemyError



DATABASE_URL = os.getenv("DATABASE_URL")

Base = declarative_base()

class PositionEnum(enum.Enum):
    MLA = 'MLA'
    MP = 'MP'

def get_engine():
    return create_engine(DATABASE_URL)

class InitModel(Base):
    __abstract__ = True
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}

    @classmethod
    def get_all(cls, filters=None):
        if filters is None:
            filters = {}

        engine = get_engine()
        Session = sessionmaker(bind=engine)
        with Session() as session:
            try:
                query = session.query(cls)
                
                for attr, value in filters.items():
                    if value is not None and hasattr(cls, attr):
                        column = getattr(cls, attr)
                        if attr == 'id':
                            query = query.filter(column == value)
                        elif isinstance(column.property.columns[0].type, (sqlalchemy.types.String, sqlalchemy.types.Text)):
                            query = query.filter(column.ilike(f"%{value}%"))
                        else:
                            query = query.filter(column == value)

                results = query.all()
                if filters.get('id'):
                    if results:
                        return True, results[0]
                    else:
                        return False, f"No record found with ID {filters['id']}"
                return True, results

            except Exception as e:
                session.rollback()
                return False, f"An error occurred while fetching the records: {str(e)}"

    
    @classmethod
    def update(cls, id, updates):
        engine = get_engine()
        Session = sessionmaker(bind=engine)
        with engine.begin() as connection:
            session = Session(bind=connection)
            try:
                record = session.query(cls).filter_by(id=id).first()
                if not record:
                    return False, "Record not found."
                
                if issubclass(cls, RoleModel) and getattr(record, 'restricted', False):
                    return False, f"The record '{id}' cannot be updated because it is restricted."
 
                for field, new_value in updates.items():
                    if hasattr(record, field):
                        print(f"Updating field: {field} with value: {new_value}")  
                        setattr(record, field, new_value)
                    else:
                        print(f"Field '{field}' not found in {cls.__name__}.")  
                        return False, f"Field '{field}' not found in {cls.__name__}."
                
                record.updated_at = datetime.utcnow()
                session.commit()
                return True, record.to_dict()
            except Exception as e:
                session.rollback()
                return False, f"An error occurred while updating the record: {str(e)}"

    @classmethod
    def create_record(cls, data):
        engine = get_engine()
        Session = sessionmaker(bind=engine)
        with engine.begin() as connection:
            session = Session(bind=connection)

            try:
                if issubclass(cls, UserModel):
                    existing_user = session.query(cls).filter_by(username=data['username']).first()
                    if existing_user:
                        return False, "Username already taken"

                    constituency_id = data.get('constituency_id')
                    if not constituency_id or not session.query(ConstituencyModel).filter_by(id=constituency_id).first():
                        return False, "Invalid constituency ID"

                elif issubclass(cls, ConstituencyModel):
                    existing_constituency = session.query(cls).filter_by(id=data.get('id')).first()
                    if existing_constituency:
                        return False, "Constituency ID already exists"

                elif issubclass(cls, CandidateModel):
                    user_id = data.get('user_id')
                    if user_id and session.query(UserModel).filter_by(id=user_id).first() is None:
                        return False, "User ID does not exist"

                elif issubclass(cls, ResultModel):
                    result_id = data.get('id')
                    if result_id and session.query(cls).filter_by(id=result_id).first():
                        return False, "Result ID already exists"

                record = cls()
                for field, value in data.items():
                    setattr(record, field, value)

                session.add(record)
                session.commit()
                return True, record.to_dict()

            except IntegrityError as e:
                session.rollback()
                if 'Duplicate entry' in str(e):
                    if 'username' in str(e):
                        return False, "Username already taken"
                    elif 'constituency' in str(e):
                        return False, "Constituency ID already exists"
                    elif 'result' in str(e):
                        return False, "Result ID already exists"
                print(f"Integrity error occurred: {e}")
                return False, f"An error occurred while creating the record: {e}"

            except Exception as e:
                session.rollback()
                print(f"Error occurred: {e}")
                return False, f"An error occurred while creating the record: {e}"

    @classmethod
    def delete(cls, id):
        engine = get_engine()
        Session = sessionmaker(bind=engine)
        session = Session()
        try:
            
            record = session.query(cls).filter_by(id=id).one_or_none()
            if not record:
                return False, f"No record found with ID {id}."

        
            if issubclass(cls, UserModel):
                
                session.query(CandidateModel).filter_by(user_id=id).delete(synchronize_session=False)
                session.query(VoteModel).filter_by(user_id=id).delete(synchronize_session=False)

         
            session.delete(record)
            session.commit()
            return True, "Record deleted successfully"

        except SQLAlchemyError as e:
            session.rollback()
            return False, f"An error occurred: {str(e)}"

        finally:
            session.close()

class UserModel(InitModel):
    __tablename__ = "users"
    username = Column(String(50), unique=True, index=True)
    hashed_password = Column(String(200))
    constituency_id = Column(Integer, ForeignKey('constituency.id', ondelete='SET NULL'))
    status = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    role_id = Column(Integer, ForeignKey('roles.id', ondelete='SET NULL'), default=3)

class RoleModel(InitModel):
    __tablename__ = "roles"
    role_name = Column(String(50), index=True)
    permissions = Column(String(500), default=None)
    exceptions = Column(String(500), default=None)
    restricted = Column(Boolean, default=False)

class ConstituencyModel(InitModel):
    __tablename__ = "constituency"
    name = Column(String(50), unique=True, index=True)

class CandidateModel(InitModel):
    __tablename__ = 'candidate'
    user_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'))
    constituency_id = Column(Integer, ForeignKey('constituency.id', ondelete='CASCADE'), nullable=False)
    result_id = Column(Integer, ForeignKey('results.id', ondelete='CASCADE'), nullable=False)

class VoteModel(InitModel):
    __tablename__ = "votes"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'))
    candidate_id = Column(Integer, ForeignKey('candidate.id', ondelete='CASCADE'))
    result_id = Column(Integer, ForeignKey('results.id', ondelete='CASCADE'))

    @classmethod
    def get_all(cls, filters=None):
        if filters is None:
            filters = {}

        engine = get_engine()
        Session = sessionmaker(bind=engine)

        try:
            session = Session()
            query = session.query(cls)

            if "id" in filters:
                vote_id = filters.pop("id")
                query = session.query(cls, ResultModel.constituency_id).join(ResultModel, cls.result_id == ResultModel.id).filter(cls.id == vote_id)
                result = query.first()

                if not result:
                    return False, f"No record found with ID {vote_id}"

                data = {
                    "id": result[0].id,   
                    "user_id": result[0].user_id,
                    "candidate_id": result[0].candidate_id,
                    "result_id": result[0].result_id,
                    "constituency_id": result[1] 
                }
                return True, [data]

            if "user_id" in filters:
                user_id = filters.pop("user_id")
                query = session.query(cls, ResultModel.constituency_id).join(ResultModel, cls.result_id == ResultModel.id).filter(cls.user_id == user_id)
                results = query.all()

                if not results:
                    return True, []

                data = [
                    {
                        "id": vote.id,
                        "user_id": vote.user_id,
                        "candidate_id": vote.candidate_id,
                        "result_id": vote.result_id,
                        "constituency_id": constituency_id
                    }
                    for vote, constituency_id in results
                ]
                return True, data

            if "result_id" in filters:
                result_id = filters.pop("result_id")
                query = (
                    session.query(
                        ResultModel.constituency_id,
                        func.count(cls.id).label('total_votes')
                    )
                    .join(ResultModel, cls.result_id == ResultModel.id)
                    .filter(cls.result_id == result_id)
                    .group_by(ResultModel.constituency_id)
                )

                results = query.all()

                if not results:
                    return False, f"No records found for result ID {result_id}"

                data = [
                    {
                        "result_id": result_id,
                        "constituency_id": row.constituency_id,
                        "total_votes": row.total_votes,
                    }
                    for row in results
                ]
                return True, data

            if "candidate_id" in filters:
                candidate_id = filters.pop("candidate_id")
                total_votes = (
                    session.query(func.count(cls.id).label('total_votes'))
                    .filter(cls.candidate_id == candidate_id)
                    .scalar()
                )

                if total_votes is None:
                    return True, []

                data = [{
                    "candidate_id": candidate_id,
                    "total_votes": total_votes,
                }]
                return True, data

          
            query = session.query(cls).join(ResultModel, cls.result_id == ResultModel.id)  # Ensure the join is always performed
            results = query.all()

            if not results:
                return True, []

            data = [
                {
                    "id": vote.id,
                    "user_id": vote.user_id,
                    "candidate_id": vote.candidate_id,
                    "result_id": vote.result_id,
                    "constituency_id": vote.constituency_id if hasattr(vote, 'constituency_id') else None,  # Check if attribute exists
                }
                for vote in results
            ]
            return True, data

        except SQLAlchemyError as e:
            session.rollback()
            return False, f"An error occurred while retrieving the records: {str(e)}"




class ResultModel(InitModel):
    __tablename__ = "results"
    name = Column(String(100), nullable=True)
    position = Column(SQLEnum(PositionEnum), nullable=False, primary_key=True)
    constituency_id = Column(Integer, ForeignKey('constituency.id', ondelete='CASCADE'), nullable=False)

def create_specific_tables():
    engine = get_engine()
    Base.metadata.create_all(engine)
    print("Tables created")

if __name__ == "__main__":
    create_specific_tables()
