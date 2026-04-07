# Use a slim Python base image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the server source code into the container
COPY server.py .

# Expose the application port
EXPOSE 5000

# Entrypoint runs the Flask app via gunicorn.  Gunicorn will
# automatically pick up the `app` object from server.py.
CMD ["gunicorn", "-b", "0.0.0.0:5000", "server:app"]