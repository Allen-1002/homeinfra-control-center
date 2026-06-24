FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    APP_HOME=/app \
    APP_PORT=8000 \
    LOG_LEVEL=INFO

WORKDIR ${APP_HOME}

RUN groupadd --system app && useradd --system --gid app --home-dir ${APP_HOME} app \
    && mkdir -p ${APP_HOME}/data ${APP_HOME}/logs

COPY requirements.txt ${APP_HOME}/requirements.txt
RUN pip install --no-cache-dir -r ${APP_HOME}/requirements.txt

COPY homeinfra ${APP_HOME}/homeinfra
COPY static ${APP_HOME}/static
COPY run.py ${APP_HOME}/run.py

RUN chown -R app:app ${APP_HOME}

USER app

EXPOSE 8000

CMD ["python", "/app/run.py", "--static-dir", "/app/static"]
