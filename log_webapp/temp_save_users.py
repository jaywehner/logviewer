def _save_users(users: Dict[str, Dict[str, Any]]) -> None:
    """Save users to SQLite database."""
    _init_db()
    with sqlite3.connect(USERS_DB) as conn:
        cursor = conn.cursor()
        # Clear existing users
        cursor.execute("DELETE FROM users")
        # Insert all users
        for username, data in users.items():
            cursor.execute(
                "INSERT INTO users (username, password_hash, password_changed) VALUES (?, ?, ?)",
                (username, data['password_hash'], int(data.get('password_changed', 0)))
        conn.commit()
