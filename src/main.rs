/* 
File: main.rs
Author: Carter Vincent
Date Created: 2024-12-03
Last Modified: 2024-12-03
*/

use clap::{Parser, Subcommand};

/// Define the command line arguments
#[derive(Parser)]
#[command(name = "Password Manager")]
#[command(about = "A simple password manager", long_about = None)]
struct Cli { /// Define the subcommands
    #[command(subcommand)]
    command: Commands,
}

/// Define the subcommands
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

/// Main function
fn main() {
    // Parse the command line arguments
    let cli = Cli::parse();

    // Match the subcommands
    match &cli.command {
        // Add a new password entry
        Commands::Add {
            // Get entry details
            service,
            username,
            password,
        } => { // Print the entry details
            println!(
                "Adding a new entry:\nService: {}\nUsername: {}\nPassword: {}",
                service, username, password
            );
            // TODO: Implement the logic to add a new password entry
        }
        // Retrieve a password entry
        Commands::Get { service } => {
            println!("Retrieving password for service: {}", service);
            // TODO: Implement the logic to retrieve a password
        }
        // Delete a password entry
        Commands::Delete { service } => {
            println!("Deleting entry for service: {}", service);
            // TODO: Implement the logic to delete a password entry
        }
        // List all password entries
        Commands::List => {
            println!("Listing all entries:");
            // TODO: Implement the logic to list all password entries
        }
    }
}
