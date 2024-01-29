import jwt
from flask import Flask, render_template, request, redirect, url_for, flash, session
import requests

app = Flask(__name__)
app.secret_key = "MIICWwIBAAKBgHYumsdHE5zt7owx3qYl13kaIdLWnqZ73IB9eIynzNVnQFJDCIZmaY6QR7kyB2hEsT6x6mr6GxQ4APW3PdV4UI1q"

# Set the API base URL
API_BASE_URL = "http://localhost:8000"


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        # Make a request to backend for authentication
        response = requests.post(f"{API_BASE_URL}/token", data={"username": email, "password": password})
        if response.status_code == 200:
            session["access_token"] = response.json()["access_token"]
            decoded_token = jwt.decode(session["access_token"], app.secret_key, algorithms=["HS256"])
            user_id = decoded_token.get("user_id")
            session["user_id"] = user_id
            flash("Login successful!", "success")
            return redirect(url_for("profile"))

        reason = response.json().get('detail')
        flash(f"{reason}. Please try again.", "error")

    return render_template("login.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        # Get user input from the form
        data = {
            "firstname": request.form["firstname"],
            "lastname": request.form["lastname"],
            "email": request.form["email"],
            "password": request.form["password"],
        }

        # Make a request to backend to create a new user
        response = requests.post(f"{API_BASE_URL}/register/", json=data)
        if response.status_code == 201:
            flash("Account created successfully! Please log in.", "success")
            return redirect(url_for("login"))

        reason = response.json().get('detail')
        flash(f"{reason}. Please try again.", "error")

    return render_template("signup.html")


@app.route("/profile")
def profile():
    # Make a request to backend to get the user profile
    headers = {"Authorization": f"Bearer {session.get('access_token')}"}
    response = requests.get(f"{API_BASE_URL}/profile/", headers=headers)

    if response.status_code == 200:
        user_data_list = response.json().get("users", [])
        if user_data_list:
            user_id_to_select = int(session.get("user_id", -1))

            # Find the user with the correct ID
            selected_user = next((user for user in user_data_list if user["id"] == user_id_to_select), None)

            if selected_user:
                return render_template("profile.html", user=selected_user)

    reason = response.json().get('detail')
    flash(f"{reason}. Please try again.", "error")
    return redirect(url_for("login"))


# Update the route definition in app.py
@app.route("/profile/update/<int:user_id>", methods=["POST", "PATCH"])
def update_profile(user_id):
    if "access_token" not in session:
        flash("Unauthorized. Please log in.", "error")
        return redirect(url_for("login"))

    # Extract user_id from the URL
    user_id = int(request.view_args['user_id']) if 'user_id' in request.view_args else None

    # Get user input from the form
    data = {
        "firstname": request.form["firstname"],
        "lastname": request.form["lastname"],
        "email": request.form["email"],
        "password": request.form["password"],
        "old_password": request.form["old_password"],
    }

    # Make a request to backend to update the user profile
    headers = {"Authorization": f"Bearer {session.get('access_token')}"}
    response = requests.patch(f"{API_BASE_URL}/update/{user_id}", json=data, headers=headers)

    if response.status_code == 200:
        flash("Profile updated successfully!", "success")
        return redirect(url_for("profile"))

    reason = response.json().get('detail')
    flash(f"{reason}. Please try again.", "error")
    return redirect(url_for("profile"))


@app.route("/delete_account", methods=["GET", "POST"])
def delete_account():
    # Ensure the user is logged in
    if "access_token" not in session:
        flash("Unauthorized. Please log in.", "error")
        return redirect(url_for("login"))

    # Get the user's ID from the backend using the access token
    headers = {"Authorization": f"Bearer {session['access_token']}"}
    response = requests.get(f"{API_BASE_URL}/profile/", headers=headers)

    if response.status_code == 200:

        # Make a request to backend to delete the user's account
        delete_response = requests.delete(f"{API_BASE_URL}/delete/me", headers=headers)

        if delete_response.status_code == 200:
            # Logout the user after successful account deletion
            session.pop("access_token", None)
            flash("Account deleted successfully.", "success")
            return redirect(url_for("home"))

    reason = response.json().get('detail')
    flash(f"{reason}. Please try again.", "error")
    return redirect(url_for("profile"))


@app.route("/logout")
def logout():
    session.pop("access_token", None)
    flash("Logged out successfully.", "success")
    return redirect(url_for("home"))


if __name__ == "__main__":
    app.run(debug=True)
