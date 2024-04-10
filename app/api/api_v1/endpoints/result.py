from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session
from app import database, schemas
from app.repository import url_crud
from fastapi import HTTPException, status
from typing import List

router = APIRouter()
get_db = database.get_db


@router.get("/")
def read_root():
    return {"message": "Hello, From Backend's /result!"}


@router.get("/list/{submission_id}", response_model=List[schemas.Result], status_code=status.HTTP_200_OK)
def get_all(submission_id: int, db_session: Session = Depends(get_db)):
    try:
        url_results = url_crud.get_all_result_by_submission_id(
            submission_id, db_session)
        ''' 
        for result in url_results:
            print(result)
        '''
    except Exception as e:
        url_results = []
        print(f'Error is {str(e)}')
    return url_results
