FROM python:alpine3.21
WORKDIR /app
COPY /app/requirements.txt .
RUN pip install -r requirements.txt
COPY /app .
CMD ["flask","--app", "application", "run"]
EXPOSE 5000