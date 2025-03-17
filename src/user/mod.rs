extern crate openssl;
extern crate base64;
extern crate rusqlite;
extern crate crypto_hash;

use std::time::SystemTime;
use base64::{encode, decode};
use openssl::symm::{encrypt, decrypt, Cipher};
use openssl::rand::rand_bytes;
use rusqlite::{params, Connection, Result};
use crypto_hash::{hex_digest, Algorithm};
use crate::singleton::Singleton;
use rand::prelude::*;

pub struct User {
    pub id: i32,
    pub name: String,
    pub email: String,
    pub password : String,
    pub password_aes: String,
    pub passwords: Passwords,
}


pub struct Passwords {
    passwords_chiffre: Vec<String>,
    passwords_clair: Vec<String>,
    key_aes: String,
}

impl User {
    pub fn new(name: String, email: String, password : String) -> Self {
        User {
            id: 0,
            name,
            email,
            password: Self::sha256_hash(password),
            password_aes: String::new(),
            passwords: Passwords {
                passwords_chiffre: Vec::new(),
                passwords_clair: Vec::new(),
                key_aes: Self::generate_aes_key(16),
            },
        }
    }
    pub fn find_by_id(user_id: i32) -> Result<Option<Self>> {
        let conn = Singleton::get_db_connection()?;

        let mut stmt = conn.prepare(
            r"SELECT id, name, email, password, password_aes FROM User WHERE id = ?1"
        )?;

        let user_row = stmt.query_row(params![user_id], |row| {
            Ok(User {
                id: row.get(0)?,
                name: row.get(1)?,
                email: row.get(2)?,
                password: row.get(3)?,
                password_aes: row.get(4)?,
                passwords: Passwords {
                    passwords_chiffre: Vec::new(),
                    passwords_clair: Vec::new(),
                    key_aes: row.get(4)?, // password_aes is used as key_aes
                },
            })
        });

        match user_row {
            Ok(mut user) => {
                let mut stmt = conn.prepare(
                    r"SELECT password_chiffre FROM Password WHERE user_id = ?1"
                )?;

                let password_iter = stmt.query_map(params![user.id], |row| {
                    row.get(0)
                })?;

                for password in password_iter {
                    user.passwords.passwords_chiffre.push(password?);
                }

                Ok(Some(user))
            },
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None), // No user found
            Err(err) => Err(err.into()), // Other errors
        }
    }
    pub fn sha256_hash(input: String) -> String {
        let digest = hex_digest(
            Algorithm::SHA256,
            input.as_ref()
        );
        return digest
    }

    fn generate_aes_key(key_len: usize) -> String {
        let mut key = vec![0; key_len];
        rand_bytes(&mut key).unwrap();
        encode(&key)
    }

    fn chiffrement(&self, data: &[u8]) -> Vec<u8> {
        let cipher = Cipher::aes_128_cbc();
        let key = decode(&self.passwords.key_aes).unwrap();
        let iv = b"\x00\x01\x02\x03\x04\x05\x06\x07\x00\x01\x02\x03\x04\x05\x06\x07";
        encrypt(cipher, &key, Some(iv), data).unwrap()
    }

    fn dechiffrement(&self, data: &[u8]) -> Vec<u8> {
        let cipher = Cipher::aes_128_cbc();
        let key = decode(&self.passwords.key_aes).unwrap();
        let iv = b"\x00\x01\x02\x03\x04\x05\x06\x07\x00\x01\x02\x03\x04\x05\x06\x07";
        decrypt(cipher, &key, Some(iv), data).unwrap()
    }

    pub fn chiffrement_passwords(&mut self) {
        for password_clair in &self.passwords.passwords_clair {
            let password_bytes = password_clair.as_bytes();
            let password_chiffre = self.chiffrement(password_bytes);
            self.passwords.passwords_chiffre.push(encode(&password_chiffre));
        }
        self.passwords.passwords_clair.clear(); // Clear plaintext passwords after encryption
    }

    pub fn dechiffrement_passwords(&mut self) {
        for password_chiffre in &self.passwords.passwords_chiffre {
            let password_bytes = decode(password_chiffre).unwrap();
            let decrypted_bytes = self.dechiffrement(&password_bytes);
            let decrypted_password = String::from_utf8_lossy(&decrypted_bytes).into_owned();
            self.passwords.passwords_clair.push(decrypted_password);
        }
    }

    // Getter and Setter for passwords_clair
    pub fn set_passwords_clair(&mut self, passwords: Vec<String>) {
        self.passwords.passwords_clair = passwords;
    }

    pub fn get_passwords_clair(&self) -> &Vec<String> {
        &self.passwords.passwords_clair
    }

    pub fn get_passwords_chiffre(&self) -> &Vec<String> {
        &self.passwords.passwords_chiffre
    }

    pub fn saveUsers(&mut self) -> Result<()> {
        let conn = Singleton::get_db_connection()?;
        conn.execute(
            r"INSERT INTO User (name, email, password, password_aes) VALUES (?1, ?2, ?3, ?4)",
            params![&self.name, &self.email, &self.password, &self.passwords.key_aes],
        )?;

        let user_id = conn.last_insert_rowid();
        self.id = user_id as i32;

        Ok(())
    }

    pub fn savePasswords(&mut self) -> Result<()> {
        let conn = Singleton::get_db_connection()?;
        for password in &self.passwords.passwords_chiffre {
            conn.execute(
                r"INSERT INTO Password (user_id, password_chiffre) VALUES (?1, ?2)",
                params![self.id, password],
            )?;
        }

        Ok(())
    }

    pub fn login(email: &str, password: &str) -> Result<Option<Self>> {
        let conn = Singleton::get_db_connection()?;
        // Prepare a query to fetch user information based on email and password
        let mut stmt = conn.prepare(
            r"SELECT id, name, email, password, password_aes FROM User WHERE email = ?1 AND password = ?2"
        )?;
        let hashed_password = User::sha256_hash(password.to_string());
        // Execute the query with provided email and password
        let user_row = stmt.query_row(params![email, hashed_password], |row| {
            Ok(User {
                id: row.get(0)?,
                name: row.get(1)?,
                email: row.get(2)?,
                password: row.get(3)?,
                password_aes: row.get(4)?,
                passwords: Passwords {
                    passwords_chiffre: Vec::new(),
                    passwords_clair: Vec::new(),
                    key_aes: "".to_string(),
                },
            })
        });

        // Handle the result of the query
        match user_row {
            Ok(mut user) => {
                // Load encrypted passwords associated with the user
                let mut stmt = conn.prepare(
                    r"SELECT password_chiffre FROM Password WHERE user_id = ?1"
                )?;

                let password_iter = stmt.query_map(params![user.id], |row| {
                    row.get(0)
                })?;

                for password in password_iter {
                    user.passwords.passwords_chiffre.push(password?);
                }

                // Update the key_aes field with the fetched password_aes
                user.passwords.key_aes = user.password_aes.clone();

                Ok(Some(user))
            },
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None), // No user found
            Err(err) => Err(err.into()), // Other errors
        }
    }
    pub fn load_from_db(mut self, conn: &Connection) -> Result<Self> {
        // Select user information from the User table
        let mut stmt = conn.prepare(
            r"SELECT id, name, email, password_aes FROM User WHERE id = ?1"
        )?;

        // Execute the query with the current user id
        let user_row = stmt.query_row(params![self.id], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
            ))
        })?;

        // Extract the row values into variables
        let (id, name, email, password_aes): (i32, String, String, String) = user_row;

        // Initialize the Passwords struct with the fetched password_aes
        self.passwords.key_aes = password_aes.clone();

        // Select all passwords associated with the user from the Password table
        let mut stmt = conn.prepare(
            r"SELECT password_chiffre FROM Password WHERE user_id = ?1"
        )?;

        // Execute the query with the current user id
        let password_iter = stmt.query_map(params![id], |row| {
            row.get(0)
        })?;

        // Collect all passwords into the passwords_chiffre vector
        for password in password_iter {
            self.passwords.passwords_chiffre.push(password?);
        }

        // Update the id and other fields of the User struct
        self.id = id;
        self.name = name;
        self.email = email;

        // Return the updated User struct
        Ok(self)
    }

    pub fn generate_password(&mut self) -> String{
        
        let mut generated_password = String::new();
        let mut rng = rand::thread_rng();
        let password_length = 12;
        let charset: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789)(*&^%$#@!~";
        for _ in 0..password_length {
            let idx = rng.gen_range(0..charset.len());
            generated_password.push(charset[idx] as char);
        }
        return generated_password;
    }

}