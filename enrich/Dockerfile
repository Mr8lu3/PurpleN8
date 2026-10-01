FROM python:3.12-alpine
RUN pip install --no-cache-dir maxminddb==2.6.2
WORKDIR /app
COPY app.py .
# Downloaded databases live in a volume so they survive restarts
VOLUME /data
EXPOSE 8080
CMD ["python", "-u", "app.py"]
