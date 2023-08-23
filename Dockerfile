# Use the official Python image as the base image
FROM python:3.8

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file into the container
COPY requirements.txt requirements.txt

# Install the required dependencies
RUN pip install -r requirements.txt

# Copy the entire application directory into the container
COPY . .

# Expose the port that Gunicorn will listen on
EXPOSE 8000

# Command to run Gunicorn with your Flask app
CMD ["gunicorn", "--bind", "0.0.0.0:8444", "kevin:app"]
