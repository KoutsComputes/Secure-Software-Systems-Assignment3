# Electronic Voting Prototype

A demonstration prototype for an Australian federal election e-voting system. This project showcases the essential components of a secure, user-friendly electronic voting platform.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Project Structure](#project-structure)
- [Setup Instructions](#setup-instructions)
  - [Local Setup (SQLite)](#local-setup-sqlite)
  - [Docker Setup (MySQL)](#docker-setup-mysql)
- [Usage Guide](#usage-guide)
- [API Reference](#api-reference)
- [Limitations & Notes](#limitations--notes)
- [Credits](#credits)

---

## Overview

The app simulates the core workflow of an Australian federal election, including voter enrolment, candidate management, voting for both the House of Representatives and the Senate (Above The Line and Below The Line), results tallying, scanned ballot import, and a public results API. The system is built using Flask and is intended for demonstration and learning, not for production use.

---

## Features

- **Voter Enrolment:** Register, check status, self-enrol, and update address.
- **Candidate Management:** Add candidates, manage party groups, and view candidate lists.
- **Voting:** 
  - House: Preference voting (comma-separated).
  - Senate: Above The Line (party names) and Below The Line (candidate IDs).
- **Overseas Voting:** Access controlled by mission codes (demo list).
- **Results:** First-preference tallies, manual recount with exclusions.
- **Scanned Ballots:** Import via CSV-like paste.
- **API:** `GET /api/results` returns JSON tallies for House and Senate.

---

## Project Structure

```
Secure-Software-Systems-Assignment3/
├─ app/
│  ├─ app.py               # Main application, models & routes
│  ├─ config.py            # Database configuration (SQLite/MySQL)
│  ├─ static/style.css     # Stylesheet
│  └─ templates/           # HTML templates
│     ├─ index.html
│     ├─ register_voter.html
│     ├─ check_enrolment.html
│     ├─ self_enrol.html
│     ├─ update_address.html
│     ├─ add_candidate.html
│     ├─ candidates.html
│     ├─ vote.html
│     ├─ vote_overseas.html
│     ├─ results.html
│     ├─ recount.html
│     └─ import_scanned.html
├─ requirements.txt        # Python dependencies
├─ Dockerfile              # Container build
├─ docker-compose.yml      # Multi-container setup
└─ README.md               # Project info
```

---

## Setup Instructions

### Local Setup (SQLite)

1. **Clone the repository:**
   ```
   git clone <repo-url>
   cd Secure-Software-Systems-Assignment3
   ```

2. **Create a virtual environment:**
   ```
   python -m venv venv
   venv\Scripts\activate   # On Windows
   ```

3. **Install dependencies:**
   ```
   pip install -r requirements.txt
   ```

4. **Run the application:**
   ```
   python app/app.py
   ```

5. **Access the app:**
   Open [http://localhost:5000](http://localhost:5000) in your browser.

---

### Docker Setup (MySQL)

1. **Build and start containers:**
   ```
   docker-compose up --build
   ```

2. **Access the app:**
   Open [http://localhost:5000](http://localhost:5000).

**Notes:**
- Live code reload: The `./app` directory is mounted into the container. Changes reflect on refresh.
- To use SQLite in Docker, remove `DATABASE_URL` from `docker-compose.yml` and the `db` service.

---

## Usage Guide

- **Enrolment:** Register as a voter, check your enrolment status, or update your address.
- **Candidate Management:** Add new candidates and manage party groupings.
- **Voting:** Cast votes for House and Senate (choose ATL or BTL).
- **Overseas Voting:** Enter a valid mission code to access overseas voting.
- **Results:** View live tallies and perform manual recounts.
- **Import Scanned Ballots:** Paste CSV-like data to include scanned ballots in results.

---

## API Reference

- **Results API:**  
  `GET /api/results`  
  Returns JSON-formatted tallies for House and Senate.

---

## Limitations & Notes

- This is a minimal prototype for demonstration and educational purposes.
- For any issues or suggestions, please open an issue or contact the maintainers.

---

## Credits
Developed for RMIT Secure Software Systems Assignment 3.

---
