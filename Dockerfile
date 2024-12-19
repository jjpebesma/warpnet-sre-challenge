FROM python:alpine3.21
WORKDIR /app
COPY /app/requirements.txt .
RUN pip install -r requirements.txt
COPY /app .
CMD ["gunicorn", "--bind", "0.0.0.0:5000" ,"application:app"]
EXPOSE 5000