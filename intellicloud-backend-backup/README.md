# IntelliCloud Backend

Part of the Senior Capstone Project

Made by: Raul Cortinas

This repository is the API and data processing engine for the IntelliCloud Intelligence Platform. It powers the dashboard by dealing with secure data collection, user validation, database interactions and audit logging.

Key Features:
- Secure API: Provides endpoints for threat management (list, create, update, delete).
- User-Specific Filtering: Ensures users see only their own data via Firebase token verification.
- Audit Logging: Tracks user actions like threat creation, updates, and deletions.

Technologies Used:
- Python (Flask): Web framework for building the API.
- Flask-CORS: Allows cross-origin requests from the frontend.
- Firebase Admin SDK: Verifies user ID tokens for secure access.
- psycopg2-binary: Connects Flask to PostgreSQL.
- dotenv: Manages secrets like database URLs securely.
- Postman: Used for API testing.

Database:
- PostgreSQL: Relational database to store threat and audit data.
- pgAdmin4: GUI tool to view and manage the database.
- Threats Table: Stores IP addresses, threat levels, descriptions, and timestamps
- Audit Log Table: Records user actions with action types, user IDs, target thread IDs, and timestamps.
