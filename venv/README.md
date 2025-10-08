# THE 404 AI - Backend

## Description

This is the official backend service for **THE 404 AI**. It is a high-performance API built with Python and FastAPI that handles all server-side logic, including user authentication (registration and login), database interactions, and providing data to the frontend application.

## Prerequisites

- Python (v3.10 or newer recommended)
- `pip` package manager
- `virtualenv` for creating isolated Python environments (highly recommended)

## Local Development Setup

Follow these steps to get the backend server running on your local machine.

### 1. Clone the Repository


### 2. Create and Activate a Virtual Environment

This step creates an isolated environment for the project's dependencies.

Create the virtual environment
python -m venv venv

Activate the environment (command differs by OS/shell)
On Windows (PowerShell):
.\venv\Scripts\activate

On Windows (Command Prompt):
.\venv\Scripts\activate.bat

On macOS and Linux:
source venv/bin/activate


### 3. Install Dependencies

First, ensure you have a `requirements.txt` file by running `pip freeze > requirements.txt` inside your activated virtual environment. Then, install all the required Python packages.

pip install -r requirements.txt


### 4. Run the Development Server

Start the FastAPI server using `uvicorn`. The `--reload` flag enables hot-reloading, which automatically restarts the server when you make code changes.


By default, the API will be available at `http://127.0.0.1:8000`.

## Important Notes

- **CORS Configuration**: If you change the port or domain of your frontend application, remember to update the `origins` list in the `CORSMiddleware` configuration inside `main.py`.
- **Database**: This project uses a local `404_ai.db` SQLite database file, which is automatically created when the server first runs. This file is excluded from Git via `.gitignore`.
- **Password Hashing**: Passwords are securely hashed using `bcrypt`. Due to a known limitation of the `bcrypt` algorithm, passwords are truncated to 72 bytes before hashing.

## To run

USE---> uvicorn main:app --reload 
