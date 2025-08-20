FROM python:3.11.1-slim

ENV PYTHONDONTWRITEBYTECODE=1

ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app/

EXPOSE 5000

RUN useradd -m appuser
USER appuser

CMD ["gunicorn", "-b", "0.0.0.0:5001", "app:app"]