FROM python:3.11-slim

LABEL maintainer="CloudGuard" \
      description="AWS IAM Risk Analyzer — multi-layer security scanner"

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
#   docker build -t cloudguard .
#   docker run --rm -v $(pwd)/policies:/app/policies cloudguard policies/
#   docker run --rm -v $(pwd)/policies:/app/policies cloudguard policies/ --graph
#   docker run --rm -e AWS_ACCESS_KEY_ID=... -e AWS_SECRET_ACCESS_KEY=... cloudguard --live --graph
