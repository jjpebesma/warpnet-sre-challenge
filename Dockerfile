FROM python:alpine3.21
WORKDIR /app
COPY /app/requirements.txt .
RUN pip3 install -r requirements.txt
RUN opentelemetry-bootstrap -a install
COPY /app .
CMD ["opentelemetry-instrument", "--traces_exporter", "otlp", "--metrics_exporter", "otlp", "--service_name", "sre-challenge", "flask", "--app", "application", "run"]
EXPOSE 5000