import sqlite3

# Connect to database
conn = sqlite3.connect('advanced_encryption.db')
c = conn.cursor()

# Create new users table without mobile
c.execute("""
    CREATE TABLE IF NOT EXISTS users_new (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        salt BLOB NOT NULL,
        is_verified INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
""")

# Copy data from old table to new (excluding mobile column)
c.execute("""
    INSERT INTO users_new (id, username, email, password_hash, salt, is_verified, created_at)
    SELECT id, username, email, password_hash, salt, is_verified, created_at
    FROM users
""")

# Drop old table
c.execute("DROP TABLE users")

# Rename new table to users
c.execute("ALTER TABLE users_new RENAME TO users")

# Recreate indexes
c.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
c.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")

conn.commit()
conn.close()

print("✅ Database updated successfully!")
print("✅ Mobile column removed from users table")
