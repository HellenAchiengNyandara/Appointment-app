from app import app

# This is for gunicorn
application = app

if __name__ == "__main__":
    app.run()