FROM python:3.12-slim
WORKDIR /app
ENV PYTHONUNBUFFERED=1 HOST=0.0.0.0 PORT=8000 SECURESUM_DB=/app/data/securesum.db
COPY requirements.txt .
RUN pip install --no-cache-dir fastapi uvicorn google-auth requests
COPY backend ./backend
COPY frontend ./frontend
COPY run.py .
RUN mkdir -p /app/data
EXPOSE 8000
CMD ["python", "run.py"]
