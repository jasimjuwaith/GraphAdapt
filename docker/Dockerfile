FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install build dependencies required by native Python packages.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./requirements.txt

RUN python -m pip install --upgrade pip \
    && python -m pip install -r requirements.txt

# Copy only application source so local files such as .env and project data
# are not included in the image build context layer.
COPY src/ ./src/

RUN groupadd --system app \
    && useradd --system --gid app --create-home app \
    && chown -R app:app /app
USER app

EXPOSE 8000

#CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000"]

CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000"]
