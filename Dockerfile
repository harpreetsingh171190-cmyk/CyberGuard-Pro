FROM python:3.11-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY requirements-app.txt .
RUN pip install --no-cache-dir -r requirements-app.txt
COPY app ./app
COPY cyberguard_threat_intel.py ./cyberguard_threat_intel.py
COPY models ./models
RUN useradd --create-home --uid 10001 cyberguard && mkdir -p /app/data && chown -R cyberguard:cyberguard /app/data
USER cyberguard
EXPOSE 8000
CMD ["uvicorn","app.api:app","--host","0.0.0.0","--port","8000"]
