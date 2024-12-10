/* 
File: main.rs
Author: Carter Vincent
Date Created: 2024-12-03
Last Modified: 2024-12-03
*/

use aes::cipher;
use clap::{Parser, Subcommand}; // Command-line parsing
use rusqlite::{params, Connection}; // SQLite database
use serde::{Deserialize, Serialize}; // Serialization/deserialization
use std::error::Error; // Error handling
use aes_gcm::{Aes256Gcm, Key, Nonce, Error as AesGcmError};
use std::error::Error as StdError; // Import StdError trait
use std::fmt;

#[derive(Debug)]
enum CustomError {
    AesGcm(AesGcmError),
    Utf8Error(std::string::FromUtf8Error),
    // Add other error types here
}

impl fmt::Display for CustomError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CustomError::AesGcm(e) => write!(f, "AES-GCM error: {}", e),
            CustomError::Utf8Error(e) => write!(f, "UTF-8 error: {}", e),
            // Handle other error types here
        }
    }
}

impl Error for CustomError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            CustomError::AesGcm(e) => Some(e),
            CustomError::Utf8Error(e) => Some(e),
            // Handle other error types here
        }
    }
}

impl From<AesGcmError> for CustomError {
    fn from(err: AesGcmError) -> CustomError {
        CustomError::AesGcm(err)
    }
}

impl From<std::string::FromUtf8Error> for CustomError {
    fn from(err: std::string::FromUtf8Error) -> CustomError {
        CustomError::Utf8Error(err)
    }
}
use aes_gcm::aead::{Aead, KeyInit}; // AES-GCM encryption
use rand::Rng; // Random number generation
use rpassword::read_password; // Read password from stdin
use pbkdf2::pbkdf2_hmac; // Key derivation function


/// Define the command line arguments
#[derive(Parser)]
#[command(name = "Password Manager")]
#[command(about = "A secure CLI-based password manager", long_about = None)]
struct Cli { 
    // Define the subcommands
    #[command(subcommand)]
    command: Commands,
}

// Define the subcommands for the password manager
#[derive(Subcommand)]
enum Commands {
    // add new entry in the password manager - each entry has name of service/site, username, password
    Add { 
        // Name
        service: String,
        // Username
        username: String,
        // Password
        password: String,
    },
    // retrieve password entry
    Get {
        // Name
        service: String,
    },
    // delete password entry
    Delete {
        // Name
        service: String,
    },
    // list all password entries
    List,
}

/// Represents a password entry
#[derive(Serialize, Deserialize)]
struct PasswordEntry {
    service: String,
    username: String,
    password: Vec<u8>, // Encrypted password
}

fn establish_connection() -> Result<Connection, rusqlite::Error> {
    let conn = Connection::open("passwords.db")?;
    Ok(conn)
}

fn initialize_database(conn: &Connection) -> Result<(), rusqlite::Error> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS passwords (
            service_name TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            password BLOB NOT NULL
        )",
        [],
    )?;
    Ok(())
}


/// Prompt user for the master password
fn prompt_master_password() -> String {
    println!("Enter your master password: ");
    read_password().expect("Failed to read password")
}

fn derive_key(password: &str, salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2_hmac::<sha2::Sha256>(password.as_bytes(), salt, 100_000, &mut key);
    key
}

fn encrypt_password(key: &[u8; 32], password: &str) -> Result<Vec<u8>, CustomError> {
    let mut rng = rand::thread_rng();
    let nonce_bytes: [u8; 12] = rng.gen();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let key = Key::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    let encrypted_password = cipher.encrypt(&nonce, password.as_bytes()).map_err(CustomError::AesGcm)?;
    Ok(encrypted_password)
}

fn decrypt_password(key: &[u8; 32], encrypted_password: &[u8]) -> Result<String, CustomError> {
    let key = Key::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    let decrypted_password = cipher.decrypt(&Nonce::from_slice(&encrypted_password[0..12]), &encrypted_password[12..]).map_err(CustomError::AesGcm)?;
    Ok(String::from_utf8(decrypted_password)?)
}

fn add_entry(conn: &Connection, entry: &PasswordEntry) -> Result<(), rusqlite::Error> {
    conn.execute(
        "INSERT OR REPLACE INTO passwords (service_name, username, password) VALUES (?1, ?2, ?3)",
        params![entry.service, entry.username, entry.password],
    )?;
    Ok(())
}

fn get_entry(conn: &Connection, service_name: &str) -> Result<PasswordEntry, Box<dyn std::error::Error>> {
    let mut stmt = conn.prepare("SELECT service_name, username, password FROM passwords WHERE service_name = ?1")?;
    let mut rows = stmt.query(params![service_name])?;
    if let Some(row) = rows.next()? {
        let entry = PasswordEntry {
            service: row.get(0)?,
            username: row.get(1)?,
            password: row.get(2)?,
        };
        Ok(entry)
    } else {
        Err("Service not found".into())
    }
}

fn delete_entry(conn: &Connection, service_name: &str) -> Result<(), rusqlite::Error> {
    let affected = conn.execute("DELETE FROM passwords WHERE service_name = ?1", params![service_name])?;
    if affected == 0 {
        return Err(rusqlite::Error::QueryReturnedNoRows);
    }
    Ok(())
}

fn list_entries(conn: &Connection) -> Result<(), Box<dyn std::error::Error>> {
    let mut stmt = conn.prepare("SELECT service_name, username FROM passwords")?;
    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    println!("Stored Password Entries:");
    for row in rows {
        let (service_name, username) = row?;
        println!("Service: {}, Username: {}", service_name, username);
    }
    Ok(())
}

fn main() -> Result<(), CustomError> {
    let cli = Cli::parse();

    // Prompt for master password
    let master_password = prompt_master_password();

    // Use a constant salt or store it securely
    let salt = b"some constant salt";

    // Derive the key
    let key = derive_key(&master_password, salt);

    // Establish database connection
    let conn = establish_connection()?;
    initialize_database(&conn)?;

    // Match the subcommands
    match &cli.command {
        Commands::Add { service, username, password } => {
            let encrypted_password = encrypt_password(&key, password)?;
            let entry = PasswordEntry {
                service: service.clone(),
                username: username.clone(),
                password: encrypted_password,
            };
            add_entry(&conn, &entry)?;
            println!("Entry for '{}' added successfully.", service);
        }
        Commands::Get { service } => {
            match get_entry(&conn, service) {
                Ok(entry) => {
                    let decrypted_password = decrypt_password(&key, &entry.password)?;
                    println!("Service: {}\nUsername: {}\nPassword: {}", entry.service, entry.username, decrypted_password);
                }
                Err(e) => println!("Error: {}", e),
            }
        }
        Commands::Delete { service } => {
            match delete_entry(&conn, service) {
                Ok(_) => println!("Entry for '{}' deleted successfully.", service),
                Err(_) => println!("No entry found for '{}'.", service),
            }
        }
        Commands::List => {
            list_entries(&conn)?;
        }
    }

    Ok(())
}
