FROM mcr.microsoft.com/playwright/python:v1.58.0-jammy

WORKDIR /app

COPY . .

RUN pip install -r requirements.txt

CMD ["bash", "-c", "cd backend && uvicorn app:app --host 0.0.0.0 --port $PORT"]
