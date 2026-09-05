FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY systemgate ./systemgate

EXPOSE 8040
CMD ["python", "-m", "uvicorn", "systemgate.main:app", "--host", "0.0.0.0", "--port", "8040"]

