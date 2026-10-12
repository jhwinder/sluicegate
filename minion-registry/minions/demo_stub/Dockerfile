FROM python:3.12-slim
WORKDIR /app
COPY minion-registry/minions/demo_stub/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY minion-registry/minions/demo_stub/worker.py ./worker.py
CMD ["python", "worker.py"]
