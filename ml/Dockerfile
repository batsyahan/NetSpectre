FROM python:3.14-slim
WORKDIR /app
COPY requirements-server.txt .
RUN pip install --no-cache-dir -r requirements-server.txt
COPY server.py explain.py ./
COPY gen ./gen
COPY models ./models
ENV NS_ML_BIND=0.0.0.0:50051
EXPOSE 50051
CMD ["python", "server.py"]
