import urllib.parse
import os
import base64
import mysql.connector
from flask import Flask, request, render_template, redirect, url_for, session, send_file
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from PIL import Image
from io import BytesIO

app = Flask(__name__)

app.secret_key = "secretkey123"
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

db = mysql.connector.connect(
        host="34.134.231.241",
        user="root",
        password="password",
        database="photo_gallery",
        connection_timeout=600,
        port=3306
)
cursor = db.cursor(buffered=True)

#cursor.execute("SET GLOBAL wait_timeout = 600;")
#cursor.execute("SET GLOBAL net_read_timeout = 600;")
#cursor.execute("SET GLOBAL interactive_timeout = 600;")
#cursor.execute("SET GLOBAL max_allowed_packet = 64*1024*1024;")

class User(UserMixin):
        def __init__(self, id, username):
                self.id = id
                self.username = username


def reconnect():
    global db, cursor
    if db is None or not db.is_connected():
        cursor = create_connection()


@login_manager.user_loader
def load_user(user_id):
        reconnect()
        cursor.execute("SELECT id, username FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        if user:
                return User(user[0], user[1])
        return None

@app.route("/signup", methods=["GET", "POST" ])
def signup():
        if request.method == "POST":
                username = request.form["username"]
                password = request.form["password"]
                confirm_password = request.form["confirm_password"]
                hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

                if password != confirm_password:
                        return "Passwords do not match."

                try:
                        cursor.execute("INSERT INTO users (username, password_hash) VALUES (%s, %s)", (username, hashed_password))
                        db.commit()
                        return redirect(url_for("login"))
                except mysql.connector.IntegrityError:
                        return "Username already exists. Try another one."
        return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
        reconnect()
        if request.method == "POST":
                username = request.form["username"]
                password = request.form["password"]

                if not username or not password:
                        return "Username or Password missing."

                cursor.execute("SELECT id, password_hash FROM users WHERE username = %s", (username,))
                user = cursor.fetchone()

                if user and bcrypt.check_password_hash(user[1], password):
                        login_user(User(user[0], username))
                        return redirect(url_for("gallery"))

                return "Invalid credentials. Try again."
        return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
        logout_user()
        return redirect(url_for("login"))

@app.route("/search", methods=["GET"])
@login_required
def search_images():
        reconnect()
        query = request.args.get("query", "")

        cursor.execute(
                "SELECT id, image_name, image_data FROM images WHERE image_name LIKE %s AND user_id = %s",
                (f"%{query}%", current_user.id)
        )
        images = cursor.fetchall()

        # Convert binary data to base64 strings
        image_results = [
                (img[0], img[1], base64.b64encode(img[2]).decode("utf-8"))
                for img in images
        ]

        return render_template("gallery.html", images=image_results)

@app.route("/download/<path:filename>")
@login_required
def download_file(filename):
        reconnect()
        cursor.execute("SELECT image_name, image_data FROM images WHERE id = %s AND user_id = %s", (filename, current_user.id))
        result = cursor.fetchone()

        if result is None:
                return "Image not found or unauthorized", 404

        image_name, image_data = result

        if not image_name.lower().endswith(".jpeg"):
                image_name = f"{image_name}.jpeg"

        # Wrap binary data as a file-like object
        return send_file(
                BytesIO(image_data),
                mimetype="image/jpeg",
                as_attachment=True,
                download_name=image_name  # Ensure user gets the original file name
        )

@app.route("/gallery")
@login_required
def gallery():
        reconnect()
        cursor.execute("SELECT id, image_name, image_data FROM images WHERE user_id = %s", (current_user.id,))
        images = cursor.fetchall()

        encoded_images = []
        for id, name, data in images:
                encoded = base64.b64encode(data).decode("utf-8")
                encoded_images.append((id, name, encoded))

        return render_template("gallery.html", images=encoded_images)

@app.route("/")
def home():
        return "Connected to MySQL!"

@app.route("/images", methods=["GET"])
def get_images():
        reconnect()
        cursor.execute("SELECT image_url FROM imagesNew")
        images = cursor.fetchall()

        image_urls = [img[0] for img in images]
        return {"image": image_urls}

@app.route("/upload", methods=["POST"])
@login_required
def upload_file():
        reconnect()
        if "file" not in request.files:
                return "No file part"

        file = request.files["file"]
        image_name = request.form.get("image_name", "")

        if file.filename == "":
                return "No selected file"

        # Open image with Pillow
        image = Image.open(file)

        # Resize or compress image (optional resizing logic here)
        max_size = (800, 800)  # Resize if larger than this
        image.thumbnail(max_size)

        # Save compressed image to a buffer
        compressed_buffer = BytesIO()
        image.save(compressed_buffer, format="JPEG", quality=70)  # JPEG is smaller than PNG

        image_data = compressed_buffer.getvalue()

        # Insert into MySQL
        cursor.execute("INSERT INTO images (image_name, image_data, user_id) VALUES (%s, %s, %s)",
                        (image_name, image_data, current_user.id))
        db.commit()

        return redirect(url_for("gallery"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
