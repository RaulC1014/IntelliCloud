# IntelliCloud Frontend

Part of Senior Capstone Project

Made By: Raul Cortinas

This repository is the user interface for the IntelliCloud Threat Intelligence Platform. Gives the users a dashboard for security teams to view and filter live cyber threats and review audit logs of user actions. The dashboard is connected to IntelliCloud API with Firebase Authentication

Key Features:
- Live Threat Feed: Displays threat data with real time filtering by IP address and threat-level (1-10 scale).
- User Authentication: Firebase login to protect access and provide user-specific data visibility.
- Audit Log Viewer: Lists actions the logged-in user performed on the threat database.

Technologies Used:
- React.js: JavaScript library for building the user interface.
- Axios: HTTP client for sending authenticated requests to the API.
- Firebase Authentication: Provides secure user login and token management.
- Environment Variables (.env): Stores Firebase keys securely in local development 
