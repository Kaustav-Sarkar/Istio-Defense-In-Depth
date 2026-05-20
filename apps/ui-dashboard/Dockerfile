FROM python:3.12-slim

WORKDIR /app

# Copy ONLY the requirements for the UI dashboard
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code
COPY main.py .

# Expose the default Streamlit port
EXPOSE 8501

# Run the Streamlit application
ENTRYPOINT ["streamlit", "run", "main.py", "--server.port=8501", "--server.address=0.0.0.0"]