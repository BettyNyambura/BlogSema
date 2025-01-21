from app import create_app, db
# from app.models import User, Blog

# Create the app instance
app = create_app()

# Push the application context before calling db.create_all()
with app.app_context():
    db.create_all()

print("Database tables created successfully!")