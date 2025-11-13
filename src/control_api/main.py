"""
Control API for the Token Emulator Harness
"""
from fastapi import FastAPI

app = FastAPI()

@app.post("/reset_all")
async def reset_all():
    return {"status": "reset triggered"}

@app.post("/issue_seed")
async def issue_seed(type: str):
    return {"seed": "PLACEHOLDER_FOR_"+type.upper()}
