AUTH SYSTEM - README

How to run:

1. Move the 'auth_system' folder into your project, e.g., Ransomware_Project/dashboard/auth_system
2. Set environment variables for SMTP (recommended) and optionally AUTH_SECRET_KEY and AUTH_PORT
   Example (Linux):
     export SMTP_HOST="smtp.gmail.com"
     export SMTP_PORT="587"
     export SMTP_USER="youremail@gmail.com"
     export SMTP_PASS="your_app_password"
     export FROM_EMAIL="youremail@gmail.com"
     export AUTH_PORT=5001
3. Install requirements in your venv:
     pip install flask pyjwt werkzeug
4. Run:
     python3 auth_app.py
5. Open in browser:
     http://127.0.0.1:5001/register
     http://127.0.0.1:5001/login

Notes:
 - After successful verification, the app redirects to http://127.0.0.1:5000/ (your main dashboard). Change AUTH_PORT or redirect target in auth_app.py if needed.
 - Tokens expire in 10 minutes by default. You can change via AUTH_JWT_EXP_MINUTES env var.
