from flask import Flask, render_template, request, redirect, url_for, flash, session
import requests

app = Flask(__name__)
app.secret_key = "your_secret_key"  # Change this to a secure key in production

# Set the API base URL
API_BASE_URL = "http://localhost:8000"  # Change this to your backend API URL


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        # Make a request to your backend for authentication
        response = requests.post(f"{API_BASE_URL}/token", data={"username": email, "password": password})
        if response.status_code == 200:
            session["access_token"] = response.json()["access_token"]
            print(response.json())

            session["user_id"] = email
            print(session)
            flash("Login successful!", "success")
            return redirect(url_for("profile"), user_id=user_id)

        flash("Invalid credentials. Please try again.", "error")

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

        # Make a request to your backend to create a new user
        response = requests.post(f"{API_BASE_URL}/register/", json=data)
        if response.status_code == 201:
            flash("Account created successfully! Please log in.", "success")
            return redirect(url_for("login"))

        flash("Error creating account. Please try again.", "error")

    return render_template("signup.html")


@app.route("/profile")
def profile():
    # Make a request to your backend to get the user profile
    headers = {"Authorization": f"Bearer {session.get('access_token')}"}
    response = requests.get(f"{API_BASE_URL}/profile/", headers=headers)

    # Retrieve the user_id from the query parameters
    user_id = request.args.get("user_id")

    if response.status_code == 200:
        user_data_list = response.json().get("users", [])
        print(user_data_list)

        if user_data_list:
            user_id_to_select = int(session.get("id", -1))  # Replace with your actual session attribute name
            print(session)
            print(user_id_to_select)

            # Find the user with the correct ID
            selected_user = next((user for user in user_data_list if user["id"] == user_id_to_select), None)

            if selected_user:
                print(f"Selected user data: {selected_user}")
                return render_template("profile.html", user=selected_user)

    flash("Unauthorized. Please log in.", "error")
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

    # Make a request to your backend to update the user profile
    headers = {"Authorization": f"Bearer {session.get('access_token')}"}
    response = requests.patch(f"{API_BASE_URL}/update/{user_id}", json=data, headers=headers)

    if response.status_code == 200:
        flash("Profile updated successfully!", "success")
        return redirect(url_for("profile"))

    flash(f"Error updating profile. {response.reason}. Please try again.", "error")
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
        user_data = response.json()["users"][0]

        # Make a request to your backend to delete the user's account
        delete_response = requests.delete(f"{API_BASE_URL}/delete/me", headers=headers)

        if delete_response.status_code == 200:
            # Logout the user after successful account deletion
            session.pop("access_token", None)
            flash("Account deleted successfully.", "success")
            return redirect(url_for("home"))

    flash("Error deleting account. Please try again.", "error")
    return redirect(url_for("profile"))


@app.route("/logout")
def logout():
    session.pop("access_token", None)
    flash("Logged out successfully.", "success")
    return redirect(url_for("home"))


if __name__ == "__main__":
    app.run(debug=True)
