# Web Client Application - Movie Library Manager

This is a CLI-based web client designed to interact with a REST API for managing a movie library. The client handles multi-tier authentication (Session Cookies for administrative tasks and JWT for library access), user management, and full CRUD operations for movies and collections.

---

## Key Features

- **Multi-Role Authentication:** Separate flows for Admin and Regular Users.
- **State Management:** Automatically stores and manages session cookies and JWT tokens.
- **Robust Network Layer:** Centralized helper function to handle headers, cookies, and tokens dynamically.
- **Complete CRUD Operations:** Full management of movies and user-curated movie collections.

---

## Component Architecture & Implemented Functions

The client processes incoming commands from the terminal using the following core functions, categorized by their structural purpose:

### 1. Network & Helper Layer
*   `send_jwt_request`: The backbone of the client's network communication. Automatically injects the active session cookie and/or JWT token into HTTP requests (`GET`, `POST`, `PUT`, `DELETE`) if they are available.

### 2. Admin Management
*   `handle_login_admin`: Prompts for admin credentials via standard input, sends a `POST` request for authentication, and securely stores the received session cookie.
*   `handle_add_user`: Allows the admin to create a new regular user by sending a `POST` request with the new credentials *(Admin-only privilege)*.
*   `handle_get_users`: Fetches and displays a list of all existing users via a `GET` request *(Admin-only privilege)*.
*   `handle_delete_user`: Prompts for a username and sends a `POST` request to remove that user from the system *(Admin-only privilege)*.
*   `handle_logout_admin`: Sends a `GET` request to terminate the admin session and clears the stored session cookie.

### 3. User Authentication & Access
*   `handle_login`: Prompts for user credentials and the associated admin username, sends a `POST` request to log in, and saves the session cookie.
*   `handle_get_access`: Requests a JWT token via a `GET` request, which is required to unlock access to the movie library features.
*   `handle_logout`: Sends a `GET` request to safely log out the current user and clears the stored session cookie.

### 4. Movie Library Management
*   `handle_get_movies`: Sends a `GET` request to retrieve all available movies, displaying their titles and unique IDs.
*   `handle_get_movie`: Prompts for a specific movie ID, sends a `GET` request, and displays detailed information about that movie.
*   `handle_add_movie`: Collects movie details (title, year, description, rating) from the user and sends a `POST` request to append it to the library *(Requires JWT)*.
*   `handle_update_movie`: Prompts for an existing movie ID and new details, then sends a `PUT` request to update the record *(Requires JWT)*.
*   `handle_delete_movie`: Prompts for a movie ID and sends a `DELETE` request to remove it from the library *(Requires JWT)*.

### 5. Movie Collections Management
*   `handle_get_collections`: Retrieves and displays a list of all existing movie collections (IDs and titles) via a `GET` request.
*   `handle_get_collection`: Prompts for a collection ID and displays its title, owner, and the list of containing movies.
*   `handle_add_collection`: Creates a new collection by requesting a title and a list of movie IDs, sending a `POST` request to initialize it, and linking the movies.
*   `handle_add_movie_to_collection`: Adds a specific movie to an existing collection using a `POST` request containing both IDs.
*   `handle_delete_collection`: Deletes an entire collection via a `DELETE` request based on its ID.
*   `handle_delete_movie_from_collection`: Removes a specific movie from a collection via a `DELETE` request.

### 6. Application Control
*   `handle_exit`: Gracefully terminates the application. It closes the active server connection, wipes the JWT token and session cookies from memory, and stops execution.

---

## Requirements & Installation

1. Clone the repository.
2. Ensure you have the required dependencies installed (e.g., standard HTTP parsing libraries or wrappers used in your project).
3. Compile the project using your project's build system (e.g., `make` or `gcc`).

```bash
# Example compilation (adjust based on your actual build files)
make
./client