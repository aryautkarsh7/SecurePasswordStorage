FROM python:3.11-slim

WORKDIR /app

COPY . /app

ENV PORT=8000
ENV HOST=0.0.0.0
ENV ALLOWED_HOSTS=*

EXPOSE 8000

CMD ["python3", "app.py"]
