extern crate rusqlite;

use rusqlite::{Connection, Result};

pub struct Singleton;

impl Singleton {
    pub fn get_db_connection() -> Result<Connection> {
        let conn = Connection::open("TrustCore.db")?;
        Ok(conn)
    }

    pub fn create_tables(conn: &Connection) -> Result<()> {
        conn.execute(
            r"CREATE TABLE IF NOT EXISTS User (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,        -- Store plain password
            password_aes TEXT NOT NULL     -- Store encrypted/hashed password (optional)
        )",
            [],
        )?;

        conn.execute(
            r"CREATE TABLE IF NOT EXISTS Password (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            password_chiffre TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES User(id)
        )",
            [],
        )?;

        Ok(())
    }
}
