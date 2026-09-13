FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt /app/requirements.txt

RUN pip install --no-cache-dir -i https://mirrors.aliyun.com/pypi/simple/ \
    --trusted-host mirrors.aliyun.com \
    -r /app/requirements.txt

COPY agent_app.py /app/agent_app.py
COPY entity_resolver.py /app/entity_resolver.py
COPY token_usage_store.py /app/token_usage_store.py
COPY tool_runtime.py /app/tool_runtime.py
COPY tools /app/tools
COPY memory /app/memory
COPY guardrails /app/guardrails
COPY alerting /app/alerting
COPY reliability /app/reliability
COPY data /app/bootstrap_data

EXPOSE 9300

CMD ["uvicorn", "agent_app:app", "--host", "0.0.0.0", "--port", "9300"]
