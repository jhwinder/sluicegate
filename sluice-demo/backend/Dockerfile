FROM python:3.11-slim AS core-builder

WORKDIR /build
RUN pip install --no-cache-dir build
COPY open-core/ ./open-core/
RUN python -m build --wheel --outdir /wheels ./open-core

FROM python:3.11-slim

WORKDIR /app
COPY sluice-demo/backend/requirements.txt .
COPY --from=core-builder /wheels /wheels
RUN pip install --no-cache-dir /wheels/sg_core-*.whl \
	&& pip install --no-cache-dir -r requirements.txt

COPY sluice-demo/backend/app ./app

ENV PYTHONUNBUFFERED=1
EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]