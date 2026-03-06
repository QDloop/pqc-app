# Quantum-Inspired Secure Lock & Access Control System

This project contains a native Android application (React Native) and a Python Flask backend implementing Post-Quantum Cryptography (Mocked for demo).

## Prerequisites

- [Node.js](https://nodejs.org/)
- [Python 3.8+](https://www.python.org/)
- Android Studio / Emulator or Expo Go app on physical device.

## Structure

- `backend/`: Flask API with mock PQC modules.
- `frontend/`: React Native Expo app.

## Setup & Running

### 1. Backend

```bash
cd backend
pip install -r requirements.txt
python app.py
```

The backend runs on `http://localhost:5000`.

### 2. Frontend (Android App)

```bash
cd frontend
npm install
npx expo start
```

- Press `a` to run on Android Emulator.
- Scan QR code with Expo Go on Android device.

## Login Credentials

**User Role:**
- Email: `user@example.com`
- Password: `password`

**Admin Role:**
- Email: `admin@example.com`
- Password: `admin`

**Lock Device Role:**
- Device ID: `lock1`
- Token: `secret1`
