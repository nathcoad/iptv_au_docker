FROM python:3.12-slim

WORKDIR /usr/src/app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 80/tcp

ENV IS_DOCKER=1
STOPSIGNAL SIGTERM

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import sys, urllib.request; url='http://127.0.0.1/healthz'; \
resp=urllib.request.urlopen(url, timeout=4); \
sys.exit(0 if 200 <= resp.getcode() < 300 else 1)"

CMD [ "python", "-u", "./app.py" ]
