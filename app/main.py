from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from mangum import Mangum

from app import models
from app.database import engine

from app.api.api_v1.api import router as router_v1

models.Base.metadata.create_all(bind=engine)

app = FastAPI()
handler = Mangum(app)

origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def read_root():
    return {"message": "Hello, From Backend!"}


# API Endpoints
app.include_router(router_v1, prefix="/api/v1")
