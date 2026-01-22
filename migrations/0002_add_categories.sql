-- Create categories table
CREATE TABLE categories (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Add category_id to posts
-- Note: SQLite does not support adding columns with foreign key constraints easily in one go, 
-- but D1 supports standard SQLite syntax.
ALTER TABLE posts ADD COLUMN category_id INTEGER REFERENCES categories(id);
