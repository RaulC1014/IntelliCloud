# IntelliCloud
Senior Capstone Project

Made by: Raul Cortinas

IntelliCloud is a secure cloud-native threat intelligence platform designed to help security teams detect, track, and manage cyber threats targeting cloud-based infrastructures. It provides both backend services and an interactive frontend dashboard to deliver real-time insights into suspicious activity.

Key Capabilities:
- Live Threat Monitoring: View and filter suspicious IPs, attack patterns, and threat levels (1-10 scale).
- User-Specific Data access: Secure access via Firebase Authentication.
- Audit Logging: Tracks user actions on the platform for accountability.
- Role-Based Access Control (soon): Different levels of access for analysts, admins, and auditors.
- Historical Threat Trends (soon): Visualization of past attacks over time.

Tech Stack:

- Frontend:
  - React.js (Dashboard UI)
  - Axios (API requests)
  - Firebase Authentication (User Login & Token Management)

- Backend:
  - Python Flask API
  - PostgreSQL Database
  - Firebase Admin SDK for token verification
  - Audit Logging System
  - psycopg2-binary (Database Connection)
  - Flask-CORS (Frontend-Backend Communication)
  - dotenv (Environment Config Management)

- Database:
  - PostgreSQL for data storage
  - pgAdmin4 for management and visualization

