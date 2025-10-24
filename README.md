# Flask Prototype App

A simple web application using Flask, MySQL, SQLAlchemy, and Docker.  
Features:
- List users
- Add new users

## Project Structure

```
Secure-Software-Systems-Assignment3\Secure-Software-Systems-Assignment3-RBAC\Secure-Software-Systems-Assignment3-RBAC\flask-prototype-app
flask-prototype-app/
  app/
    app.py
    config.py
    templates/
      index.html
      add_user.html
    static/
      style.css
  requirements.txt
  docker-compose.yml
  Dockerfile
```

## Setup & Usage

1. **Clone the repository**  
   Place all files as shown above.

2. **Configure MySQL**  
   The default connection string is:
   ```
   mysql+mysqlconnector://root:password@db:3306/flask_db
   ```
   Update `app/config.py` if needed.

3. **Build and run with Docker Compose**
   ```bash
   docker-compose build
   docker-compose up
   ```

4. **Initialize the database**
   Enter the web container:
   ```bash
   docker-compose exec web flask shell
   ```
   Then run:
   ```python
   from app import db
   db.create_all()
   ```

5. **Access the app**
   Open [http://localhost:5000](http://localhost:5000) in your browser.

## Features

- **User List:** Shows all users in the database.
- **Add User:** Form to add a new user (username and email).

## Notes

- For development only. Do not use the built-in Flask server in production.
- Make sure MySQL container is running and accessible.

## License

MIT
