### Build stage for frontend
FROM node:18 AS build-frontend
WORKDIR /src
COPY open-core/src/sg_poledit/editor/frontend/package.json open-core/src/sg_poledit/editor/frontend/package-lock.json* ./frontend/
COPY open-core/src/sg_poledit/editor/frontend ./frontend
WORKDIR /src/frontend
RUN npm install
RUN npm run build

### Final image
FROM python:3.11-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install runtime deps
RUN apt-get update && apt-get install -y build-essential && rm -rf /var/lib/apt/lists/*

# Copy backend source
COPY open-core/src/sg_poledit/editor/backend ./backend
COPY . /app

WORKDIR /app/backend
RUN pip install --no-cache-dir -r requirements.txt

# Copy built frontend into static folder
COPY --from=build-frontend /src/frontend/dist /app/open-core/src/sg_poledit/editor/frontend/dist

EXPOSE 8080
ENV POLICIES_DIR=/policies

CMD ["python", "main.py"]
