from flask import Flask, jsonify, request, make_response, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, verify_jwt_in_request, decode_token
from flask_migrate import Migrate
import os
from flask_cors import CORS, cross_origin  # Import Flask-CORS

from werkzeug.utils import secure_filename
from datetime import timedelta, datetime  # Add datetime here
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import smtplib
from pytz import timezone
import re
from dotenv import load_dotenv
app = Flask(__name__)
from flask_cors import CORS

CORS(app, supports_credentials=True, resources={r"/*": {"origins": "http://localhost:5173"}})
def token_required(f):
    def wrapper(*args, **kwargs):
        if request.path.startswith('/uploads'):
            return f(*args, **kwargs)
        token = request.headers.get('Authorization')
        if not token:
            return {"message": "No token provided"}, 401
        return f(*args, **kwargs)
    return wrapper

@app.route('/uploads/<path:filename>')
def serve_uploads(filename):
    # Serve files from 'uploads' directory
    return send_from_directory('uploads', filename)
load_dotenv()

# Configuration
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///photography.db"  # Change to your database URI
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["JWT_SECRET_KEY"] = "supersecretkey"  # Replace with a strong secret key
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=12)
          


# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
# Public endpoints that don't require tokens
@app.before_request
def before_request():
    """
    Global token verification applied before each request.
    Skips validation for OPTIONS requests and public routes.
    """
    # Print incoming request details for debugging
    print(f"Incoming request method: {request.method}")
    print(f"Incoming request path: {request.path}")
    print(f"Authorization Header: {request.headers.get('Authorization')}")
    if request.path.startswith("/uploads") or "/packages" in request.path:
            print(f"Skipping token validation for /uploads or matching path: {request.path}")
            return None  # Skip validation for /uploads
    # Allow Flask-CORS to handle OPTIONS preflight requests
    if request.method == "OPTIONS":
        print("Skipping token validation for OPTIONS preflight request")
        return None  # Let CORS handle the preflight response
    if request.endpoint and "jwt_required" in str(app.view_functions[request.endpoint]):
        return  # Skip if `@jwt_required` is already applied
    # List of public paths that don't require authentication
    public_paths = [
        "/signin", "/forgot_password", "/reset-password",
        "/api/gallery", "/api/contact", "/uploads", "/api/packages", "/api/reviews", "/api/inquiries"
    ]

    # Check if request path matches any public path
    if any(request.path.startswith(path) for path in public_paths):
        print(f"Public path matched: {request.path}. Skipping token validation.")
        return  # Skip token validation for public paths

    print("Token validation required for this request.")
    if request.path.startswith("/api/packages") and request.method == "GET":
        return
    if request.method == "GET" and request.path == "/api/reviews":
        print(f"Public GET request matched: {request.path}. Skipping token validation.")
        return

    # Extract the Authorization header
    token = request.headers.get('Authorization', '')
    if not token or " " not in token:
        print("No token provided, returning 401")
        return jsonify({'error': 'Token is missing'}), 401

    # Verify and decode the token
    try:
        verify_jwt_in_request()
        payload = get_jwt_identity()
        print(f"Token successfully verified. Payload: {payload}")
        request.user_id = payload
    except Exception as e:
        print(f"Token validation failed: {e}")
        return jsonify({'error': 'Invalid or expired token'}), 401

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)  # Add email field
    password_hash = db.Column(db.String(128), nullable=False)

    @property
    def password(self):
        raise AttributeError("Password is not readable.")

    @password.setter
    def password(self, plaintext_password):
        self.password_hash = bcrypt.generate_password_hash(plaintext_password).decode("utf-8")

    def verify_password(self, plaintext_password):
        return bcrypt.check_password_hash(self.password_hash, plaintext_password)


# Route for Admin Sign-in
@app.route('/signin', methods=['POST'])
def signin():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    admin_user = User.query.filter_by(username=username).first()
    if not admin_user or not admin_user.verify_password(password):
        return jsonify({"error": "Invalid credentials"}), 401

    # Generate a JWT token
    access_token = create_access_token(identity=admin_user.id)
    return jsonify({"message": "Sign-in successful!", "token": access_token}), 200


@app.route('/admin-dashboard', methods=['GET'])
@jwt_required()
def admin_dashboard():
    current_user_id = get_jwt_identity()
    print(f"User ID from Token: {current_user_id}")

    user = User.query.get(current_user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    return jsonify({"id": user.id, "username": user.username, "email": user.email}), 200

class Gallery(db.Model):
    __tablename__ = "gallery"

    id = db.Column(db.Integer, primary_key=True)
    image_url = db.Column(db.String(255), nullable=False)
    caption = db.Column(db.String(255), nullable=True)
    category = db.Column(db.String(50), nullable=True)
    photo_type = db.Column(db.String(20), nullable=False)  # New column for photo type
    created_at = db.Column(db.DateTime, default=db.func.now(), nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "image_url": self.image_url,
            "caption": self.caption,
            "category": self.category,
            "photo_type": self.photo_type,
            "created_at": self.created_at.strftime("%Y-%m-%d %H:%M:%S")
        }

VALID_PHOTO_TYPES = {"portrait", "couples", "events", "cosplay", "pets", "misc"}
def validate_photo_type(photo_type):
    if photo_type not in VALID_PHOTO_TYPES:
        raise ValueError("Invalid photo type. Allowed types are: " + ", ".join(VALID_PHOTO_TYPES))
# Configure Upload Folder
UPLOAD_FOLDER = "uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}

# Utility Function to Check Allowed Files
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


# Route: Upload a Photo to the Gallery
# Route: Add a Photo URL to the Gallery
@app.post('/api/gallery/upload')
@jwt_required()
def upload_photo():
    current_user_id = get_jwt_identity()

    print(f"Current user ID: {current_user_id}")  # Debugging line

    """
    Accept an image URL and add it to the gallery.
    """
    data = request.get_json()

    # Extract fields from the request body
    image_url = data.get("image_url")
    caption = data.get("caption", "")
    category = data.get("category", "Uncategorized")
    photo_type = data.get("photo_type", "").lower()

    # Validate photo type
    try:
        validate_photo_type(photo_type)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    # Validate that image_url is provided
    if not image_url or not image_url.startswith(("http://", "https://")):
        return jsonify({"error": "Invalid or missing image URL."}), 400

    # Add record to the database
    new_photo = Gallery(
        image_url=image_url,  # Use the provided URL
        caption=caption,
        category=category,
        photo_type=photo_type
    )
    db.session.add(new_photo)
    db.session.commit()

    return jsonify({"message": "Photo added successfully!", "photo": new_photo.to_dict()}), 201


# Route: Fetch All Gallery Photos
@app.get('/api/gallery')
def get_gallery():
    """
    Fetch all gallery images with optional category or photo_type filtering.
    """
    category = request.args.get("category", None)
    photo_type = request.args.get("photo_type", None)

    query = Gallery.query

    if category:
        query = query.filter(Gallery.category.ilike(f"%{category}%"))
    if photo_type:
        query = query.filter(Gallery.photo_type.ilike(f"%{photo_type}%"))


    photos = query.all()
    return jsonify([photo.to_dict() for photo in photos]), 200



# Route: Delete a Photo
@app.delete('/api/gallery/<int:photo_id>')
@jwt_required()
def delete_photo(photo_id):
    """
    Delete a photo from the gallery.
    """
    photo = Gallery.query.get(photo_id)
    if not photo:
        return jsonify({"error": "Photo not found"}), 404

    # Remove the record from the database
    db.session.delete(photo)
    db.session.commit()

    return jsonify({"message": "Photo deleted successfully"}), 200

#--------------------------------------------------------------------------------#
class Review(db.Model):
    __tablename__ = "reviews"

    id = db.Column(db.Integer, primary_key=True)
    photo_url = db.Column(db.String(255), nullable=True)  # Store the image URL directly
    reviewer_name = db.Column(db.String(50), nullable=False)
    rating = db.Column(db.Integer, nullable=False)  # Rating out of 5
    comment = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=db.func.now(), nullable=False)
    is_approved = db.Column(db.Boolean, default=False, nullable=False)  # New field

    def to_dict(self):
        return {
            "id": self.id,
            "photo_url": self.photo_url, 
            "reviewer_name": self.reviewer_name,
            "rating": self.rating,
            "comment": self.comment,
            "is_approved": self.is_approved, 
            "created_at": self.created_at.strftime("%Y-%m-%d %H:%M:%S")
        }

@app.route('/api/reviews', methods=['POST'])
def add_review():
    """
    Add a review. The photo_url is optional.
    """
    data = request.get_json()
    photo_url = data.get("photo_url", "")  # Optional field for the image URL
    reviewer_name = data.get("reviewer_name")
    rating = data.get("rating")
    comment = data.get("comment", "")

    # Validate inputs
    if not reviewer_name or not rating:
        return jsonify({"error": "Reviewer name and rating are required."}), 400
    if not (1 <= int(rating) <= 5):
        return jsonify({"error": "Rating must be between 1 and 5."}), 400

    # Create and save the review
    review = Review(
        photo_url=photo_url,  # Store the image URL directly
        reviewer_name=reviewer_name,
        rating=int(rating),
        comment=comment
    )
    db.session.add(review)
    db.session.commit()

    return jsonify({"message": "Review added successfully!", "review": review.to_dict()}), 201

@app.get('/api/reviews/pending')
@jwt_required()
def get_pending_reviews():
    """
    Get all reviews that are pending approval.
    Admin access required.
    """
    # Check if the user is an admin (add your logic for admin verification)
    current_user_id = get_jwt_identity()
    # Example: Add logic to check if the user is an admin
    # user = User.query.get(current_user_id)
    # if not user.is_admin:
    #     return jsonify({"error": "Admin access required."}), 403

    # Query for pending reviews
    pending_reviews = Review.query.filter_by(is_approved=False).all()

    return jsonify([review.to_dict() for review in pending_reviews]), 200


@app.get('/api/reviews')
def get_reviews():
    """
    Get all approved reviews. Optionally filter by photo_url.
    """
    photo_url = request.args.get("photo_url", None)  # Optional query parameter

    query = Review.query.filter_by(is_approved=True)  # Only fetch approved reviews
    if photo_url:
        query = query.filter_by(photo_url=photo_url)

    reviews = query.all()
    return jsonify([review.to_dict() for review in reviews]), 200
@app.patch('/api/reviews/<int:review_id>/approve')
@jwt_required()  # Admin access only
def approve_review(review_id):
    """
    Approve a specific review by its ID.
    """
    # Check user permissions if needed (ensure admin access)
    current_user_id = get_jwt_identity()
    # Add logic to confirm if the user is an admin

    # Find the review
    review = Review.query.get(review_id)
    if not review:
        return jsonify({"error": "Review not found."}), 404

    # Approve the review
    review.is_approved = True
    db.session.commit()

    return jsonify({"message": "Review approved successfully!", "review": review.to_dict()}), 200


@app.delete('/api/reviews/<int:review_id>')
@jwt_required()
def delete_review(review_id):
    """
    Delete a specific review by its ID.
    """
    # Find the review by ID
    review = Review.query.get(review_id)

    # Check if the review exists
    if not review:
        return jsonify({"error": "Review not found."}), 404

    # Log the photo_url for debugging or tracking purposes (optional)
    print(f"Deleting review with ID: {review_id}, associated photo URL: {review.photo_url}")

    # Delete the review
    db.session.delete(review)
    db.session.commit()

    return jsonify({"message": f"Review with ID {review_id} deleted successfully."}), 200

@app.patch('/api/reviews/<int:review_id>')
@jwt_required()
def update_review(review_id):
    """
    Update specific fields of a review by its ID.
    Admin access required.
    """
    # Check for admin access (add your admin verification logic)
    current_user_id = get_jwt_identity()

    # Find the review
    review = Review.query.get(review_id)
    if not review:
        return jsonify({"error": "Review not found."}), 404

    data = request.get_json()

    # Update fields if provided
    if "reviewer_name" in data:
        review.reviewer_name = data["reviewer_name"]
    if "rating" in data:
        if not (1 <= int(data["rating"]) <= 5):
            return jsonify({"error": "Rating must be between 1 and 5."}), 400
        review.rating = int(data["rating"])
    if "comment" in data:
        review.comment = data["comment"]
    if "photo_url" in data:
        review.photo_url = data["photo_url"]

    # Automatically set the review to pending when updated
    review.is_approved = False

    db.session.commit()

    return jsonify({"message": "Review updated successfully and marked as pending!", "review": review.to_dict()}), 200

#----------------------------------------------------------------------------------------------------
class Inquiry(db.Model):
    __tablename__ = "inquiries"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    phone_number = db.Column(db.String(15), nullable=True)  # Optional
    call_or_text = db.Column(db.String(10), nullable=False)  # "call" or "text"
    description = db.Column(db.Text, nullable=False)
    submitted_at = db.Column(db.DateTime, default=db.func.now(), nullable=False)
    status = db.Column(db.String(20), nullable=False, default="pending")  # New status column

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "email": self.email,
            "phone_number": self.phone_number,
            "call_or_text": self.call_or_text,
            "description": self.description,
            "status": self.status,  # Include status in the response
            "submitted_at": self.submitted_at.strftime("%Y-%m-%d %H:%M:%S")
        }


@app.post('/api/contact')
def submit_inquiry():
    """
    Submit a user inquiry and notify the admin via email.
    """
    data = request.get_json()

    # Validate required fields
    required_fields = ['name', 'email', 'call_or_text', 'description']
    if not all(data.get(field) for field in required_fields):
        return jsonify({"error": f"Missing required fields: {', '.join(required_fields)}"}), 400

    name = data.get('name')
    email = data.get('email')
    phone_number = data.get('phone_number')  # Optional
    call_or_text = data.get('call_or_text').lower()
    description = data.get('description')

    if call_or_text not in ["call", "text"]:
        return jsonify({"error": "Invalid value for 'call_or_text'. Must be 'call' or 'text'."}), 400

    # Validate email format
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return jsonify({"error": "Invalid email format"}), 400

    # Save the inquiry to the database
    new_inquiry = Inquiry(
        name=name,
        email=email,
        phone_number=phone_number,
        call_or_text=call_or_text,
        description=description
    )
    db.session.add(new_inquiry)
    db.session.commit()
    local_tz = timezone("US/Eastern")  # Replace "US/Eastern" with your actual timezone
    submitted_at_local = new_inquiry.submitted_at.replace(tzinfo=timezone("UTC")).astimezone(local_tz)

    # Send email to admin
    try:
        admin_email = os.getenv("ADMIN_EMAIL")  # Admin email from environment variable
        subject = f"New Inquiry from {name}"
        body = f"""
    <html>
    <head>
        <style>
        body {{
            font-family: Arial, sans-serif;
            color: #333;
            margin: 0;
            padding: 20px;
            background-color: #f9f9f9;
        }}
        .container {{
            background: #fff;
            border-radius: 8px;
            padding: 20px;
            max-width: 600px;
            margin: 20px auto;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
        }}
        h2 {{
            color: #007bff;
        }}
        p {{
            margin: 8px 0;
            line-height: 1.5;
        }}
        .footer {{
            margin-top: 20px;
            font-size: 12px;
            color: #888;
            text-align: center;
        }}
        </style>
    </head>
    <body>
        <div class="container">
        <h2>📧 New Inquiry Received</h2>
        <p><strong>Name:</strong> {name}</p>
        <p><strong>Email:</strong> {email}</p>
        <p><strong>Phone Number:</strong> {phone_number or "N/A"}</p>
        <p><strong>Contact Preference:</strong> {call_or_text.capitalize()}</p>
        <p><strong>Description:</strong> {description}</p>
        <div class="footer">
            <p>Submitted on {submitted_at_local.strftime('%A, %B %d, %Y %I:%M %p')}</p>
            <p>&copy; Golden Hour Photography</p>
        </div>
        </div>
    </body>
    </html>
    """


        send_email(
            recipient=admin_email,
            subject=subject,
            body=body,  # Add the body here

            background_image_url=None
        )
    except Exception as e:
        print(f"Failed to send email: {str(e)}")
        return jsonify({"error": "Inquiry submitted but failed to notify the admin."}), 500

    return jsonify({"message": "Inquiry submitted successfully.", "inquiry": new_inquiry.to_dict()}), 201




def send_email(recipient, subject, body, background_image_url=None):
    """
    Sends a simple email with optional background image.
    """
    sender_email = os.getenv('EMAIL_ADDRESS')
    sender_password = os.getenv('EMAIL_PASSWORD')
    smtp_server = os.getenv('SMTP_SERVER')
    smtp_port = int(os.getenv('SMTP_PORT', 587))

    # Build plain-text body
    text_body = body  # Use the full body content

    msg = MIMEMultipart("alternative")
    msg["From"] = sender_email
    msg["To"] = recipient
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "html"))

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.send_message(msg)
        print(f"Email sent to {recipient}")
    except Exception as e:
        print(f"Email error: {str(e)}")
        raise e


@app.patch('/api/inquiries/<int:inquiry_id>')
def update_inquiry_status(inquiry_id):
    """
    Update the status of an inquiry.
    Allowed statuses: 'pending', 'contacted', 'booked', 'booked & paid', 'completed'
    """
    allowed_statuses = {"pending", "contacted", "booked", "booked & paid", "completed"}
    data = request.get_json()

    # Check if 'status' is provided
    new_status = data.get("status")
    if not new_status:
        return jsonify({"error": "The 'status' field is required."}), 400

    # Validate the new status
    if new_status not in allowed_statuses:
        return jsonify({"error": f"Invalid status. Allowed values: {', '.join(allowed_statuses)}"}), 400

    # Fetch the inquiry
    inquiry = Inquiry.query.get(inquiry_id)
    if not inquiry:
        return jsonify({"error": "Inquiry not found."}), 404

    try:
        # Update the status
        inquiry.status = new_status
        db.session.commit()
        return jsonify({"message": "Inquiry status updated successfully.", "inquiry": inquiry.to_dict()}), 200
    except Exception as e:
        print(f"Error updating inquiry status: {e}")
        return jsonify({"error": "Failed to update inquiry status."}), 500


@app.get('/api/inquiries')
def get_inquiries():
    """
    Fetch all client inquiries with optional filtering by name, phone_number, or status.
    """
    try:
        # Get query parameters from the request
        name = request.args.get("name", "").strip()
        phone_number = request.args.get("phone_number", "").strip()
        status = request.args.get("status", "").strip()

        # Build query dynamically
        query = Inquiry.query

        if name:
            query = query.filter(Inquiry.name.ilike(f"%{name}%"))  # Case-insensitive search
        if phone_number:
            query = query.filter(Inquiry.phone_number.ilike(f"%{phone_number}%"))
        if status:
            query = query.filter(Inquiry.status.ilike(f"%{status}%"))

        # Execute query with sorting
        inquiries = query.order_by(Inquiry.submitted_at.desc()).all()

        return jsonify([inquiry.to_dict() for inquiry in inquiries]), 200
    except Exception as e:
        print(f"Error fetching inquiries: {e}")
        return jsonify({"error": "Failed to fetch inquiries."}), 500

@app.delete('/api/inquiries/<int:inquiry_id>')
def delete_inquiry(inquiry_id):
    """
    Delete an inquiry by ID.
    """
    # Fetch the inquiry by ID
    inquiry = Inquiry.query.get(inquiry_id)
    if not inquiry:
        return jsonify({"error": "Inquiry not found."}), 404

    try:
        # Delete the inquiry
        db.session.delete(inquiry)
        db.session.commit()
        return jsonify({"message": f"Inquiry with ID {inquiry_id} deleted successfully."}), 200
    except Exception as e:
        print(f"Error deleting inquiry: {e}")
        return jsonify({"error": "Failed to delete the inquiry."}), 500


#-------------------------------------------------------------------------------

@app.route('/forgot_password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    username = data.get("username")

    # Validate user
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    # Generate reset token (valid for 1 hour)
    reset_token = create_access_token(identity=user.id, expires_delta=timedelta(hours=1))

    # Send reset email
    reset_link = f"http://localhost:5173/reset-password?token={reset_token}"
    subject = "Password Reset Request"
    body = f"""
    <html>
    <head>
        <style>
            body {{
                font-family: 'Arial', sans-serif;
                background-color: #f4f4f9;
                margin: 0;
                padding: 0;
                color: #333333;
            }}
            .container {{
                max-width: 600px;
                margin: 40px auto;
                background-color: #ffffff;
                border-radius: 10px;
                box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
                overflow: hidden;
            }}
            .header {{
                background: linear-gradient(to right, #4a90e2, #1453e4);
                color: #ffffff;
                text-align: center;
                padding: 20px 0;
            }}
            .header h1 {{
                margin: 0;
                font-size: 24px;
                font-weight: bold;
            }}
            .content {{
                padding: 30px;
                text-align: center;
            }}
            .content p {{
                font-size: 16px;
                line-height: 1.6;
            }}
            .reset-button {{
                display: inline-block;
                margin: 20px 0;
                padding: 12px 24px;
                background: #4a90e2;
                color: #ffffff;
                text-decoration: none;
                font-weight: bold;
                border-radius: 50px;
                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.2);
                transition: background 0.3s ease;
            }}
            .reset-button:hover {{
                background: #1453e4;
            }}
            .footer {{
                background-color: #f4f4f9;
                text-align: center;
                font-size: 12px;
                padding: 15px;
                color: #666666;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🔒 Password Reset Request</h1>
            </div>
            <div class="content">
                <p>Hello <strong>{user.username}</strong>,</p>
                <p>
                    We received a request to reset your password. Click the button below to proceed:
                </p>
                <a href="{reset_link}" class="reset-button" target="_blank">Reset Your Password</a>
                <p>If you did not request a password reset, you can safely ignore this email.</p>
                <p>For security reasons, this link will expire in 1 hour.</p>
            </div>
            <div class="footer">
                &copy; {datetime.now().year} Golden Hour Photography | All rights reserved.
            </div>
        </div>
    </body>
    </html>
    """

    try:
        send_email(user.email, subject, body)
    except Exception as e:
        return jsonify({"error": "Failed to send reset email"}), 500

    return jsonify({"message": "Password reset link has been sent to your email."}), 200

@app.post('/reset-password')
def reset_password():
    data = request.get_json()
    reset_token = request.headers.get("Authorization", "").replace("Bearer ", "")

    print(f"Token received: {reset_token}")  # Debugging line

    try:
        # Decode the token manually
        decoded_token = decode_token(reset_token)
        user_id = decoded_token.get("sub")  # Extract user ID from 'sub' field
        print(f"Decoded User ID: {user_id}")  # Debugging line
    except Exception as e:
        print(f"Token decoding failed: {str(e)}")
        return jsonify({"error": "Invalid or expired token"}), 400

    # Validate user
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    new_password = data.get("new_password")
    if not new_password:
        return jsonify({"error": "New password is required."}), 400

    # Update the user's password
    user.password = new_password  # Hashing is handled by the setter
    db.session.commit()

    return jsonify({"message": "Password has been reset successfully."}), 200


@app.route('/api/user', methods=['GET'])
@jwt_required()
def get_user():
    """
    Validate token and return user details.
    """
    try:
        current_user_id = get_jwt_identity()  # Extract user ID from the token
        user = User.query.get(current_user_id)

        if not user:
            return jsonify({"error": "User not found"}), 404

        return jsonify({
            "id": user.id,
            "username": user.username,
            "email": user.email
        }), 200

    except Exception as e:
        print(f"Error fetching user: {str(e)}")
        return jsonify({"error": "Failed to fetch user details."}), 500






#---------------------------------------------------------------------

class Package(db.Model):
    __tablename__ = "packages"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    image_url = db.Column(db.String(255), nullable=True)
    description = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=db.func.now(), nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "amount": self.amount,
            "image_url": self.image_url,
            "description": self.description,
            "created_at": self.created_at.strftime("%Y-%m-%d %H:%M:%S"),
        }

@app.post('/api/packages')
def create_package():
    """
    Create a new package with an image URL.
    """
    data = request.get_json()
    title = data.get("title")
    amount = data.get("amount")
    description = data.get("description")
    image_url = data.get("image_url", "").strip()

    # Validate required fields
    if not title or not amount:
        return jsonify({"error": "Title and amount are required."}), 400

    # Validate image URL
    if image_url and not is_valid_url(image_url):
        return jsonify({"error": "Invalid image URL."}), 400

    # Create new package
    try:
        new_package = Package(
            title=title,
            amount=float(amount),
            description=description,
            image_url=image_url,
        )
        db.session.add(new_package)
        db.session.commit()
    except Exception as e:
        return jsonify({"error": "Failed to create package."}), 500

    return jsonify({"message": "Package created successfully!", "package": new_package.to_dict()}), 201
@app.put('/api/packages/<int:package_id>')
def update_package(package_id):
    """
    Update a package by ID.
    """
    package = Package.query.get(package_id)
    if not package:
        return jsonify({"error": "Package not found."}), 404

    # Parse incoming JSON data
    data = request.get_json()

    # Update fields
    package.title = data.get("title", package.title)
    package.amount = float(data.get("amount", package.amount))
    package.description = data.get("description", package.description)
    package.image_url = data.get("image_url", package.image_url)  # Update image URL if provided

    db.session.commit()
    return jsonify({"message": "Package updated successfully!", "package": package.to_dict()}), 200

@app.delete('/api/packages/<int:package_id>')
def delete_package(package_id):
    """
    Delete a package by ID.
    """
    package = Package.query.get(package_id)
    if not package:
        return jsonify({"error": "Package not found."}), 404

    # Only delete local file paths, not external URLs
    if package.image_url and package.image_url.startswith("uploads/"):
        if os.path.exists(package.image_url):
            os.remove(package.image_url)

    db.session.delete(package)
    db.session.commit()

    return jsonify({"message": "Package deleted successfully!"}), 200
def is_valid_url(url):
    return re.match(r'^https?://', url) is not None
@app.get('/api/packages')
@cross_origin()  # Allow all origins
def get_packages():
    """
    Retrieve all packages.
    """
    try:
        packages = Package.query.all()
        return jsonify([package.to_dict() for package in packages]), 200
    except Exception as e:
        print(f"ERROR: Failed to fetch packages - {e}")
        return jsonify({"error": "Failed to fetch packages."}), 500

# Run the app
if __name__ == "__main__":
    app.run(debug=True)
