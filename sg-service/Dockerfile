FROM python:3.12-slim AS build

WORKDIR /workspace
RUN pip install --no-cache-dir uv
RUN uv tool install build
COPY pyproject.toml uv.lock ./
COPY open-core/pyproject.toml open-core/pyproject.toml
COPY open-core/README.md open-core/README.md
COPY open-core/src/ open-core/src/
COPY sg-service/pyproject.toml sg-service/pyproject.toml
COPY sg-service/src/ sg-service/src/
RUN uv build --package sg-core --out-dir /wheels \
	&& uv build --package sg-service --out-dir /wheels

FROM python:3.12-slim
WORKDIR /app
COPY sg-service/pyproject.toml /tmp/sg-service-pyproject.toml
COPY --from=build /wheels /wheels
RUN python -m venv /opt/venv \
	&& /opt/venv/bin/pip install --no-cache-dir /wheels/sg_core-*.whl /wheels/sg_service-*.whl \
	&& rm -rf /wheels /tmp/sg-service-pyproject.toml
ENV PATH="/opt/venv/bin:${PATH}"
ENV SG_DATABASE_PATH=/data/sg-service.sqlite3
EXPOSE 8443
CMD ["python", "-m", "sg_service"]
