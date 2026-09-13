FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt /app/requirements.txt

RUN pip install --no-cache-dir -i https://mirrors.aliyun.com/pypi/simple/ \
    --trusted-host mirrors.aliyun.com \
    -r /app/requirements.txt

COPY app.py /app/app.py
COPY token_usage_store.py /app/token_usage_store.py
COPY sync_engine /app/sync_engine
COPY knowledge_base /app/knowledge_base

EXPOSE 9200

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "9200"]