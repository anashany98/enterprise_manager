FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential libpq-dev \
    && pip install --upgrade pip \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install -r requirements.txt

COPY . .

ENV FLASK_APP=enterprise_manager.app
ENV FLASK_RUN_HOST=0.0.0.0

# Run the application
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app"]
