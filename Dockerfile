FROM python:3.11-slim

LABEL maintainer="Meridian" \
      description="IAM Risk Intelligence — multi-layer security scanner"

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY . .

# Default entrypoint: scan the /policies mount
ENTRYPOINT ["python", "cli.py"]
CMD ["--help"]

# Usage examples:
#   docker build -t meridian .
#   docker run --rm -v $(pwd)/policies:/app/policies meridian policies/
#   docker run --rm -v $(pwd)/policies:/app/policies meridian policies/ --graph
#   docker run --rm -e AWS_ACCESS_KEY_ID=... -e AWS_SECRET_ACCESS_KEY=... meridian --live --graph
