use std::collections::HashMap;
use std::io;

use rusqlite::Connection;

fn main() {
    // Load the config
    // Get the path to the current executable.
    let exe_path = std::env::current_exe().expect("Failed to get executable path");
    let exe_dir = exe_path
        .parent()
        .expect("Failed to get directory of executable");
    let config_path = exe_dir.join("config.toml");
    let contents = std::fs::read_to_string(config_path).expect("Failed to read config file");
    let config: HashMap<String, HashMap<String, String>> =
        toml::from_str(&contents).expect("Failed to parse config file");
    let db_path = config
        .get("database")
        .unwrap()
        .get("path")
        .expect("Failed to get database path");

    loop {
        println!("Select an option:");
        println!("1. Create database");
        println!("2. Add user");
        println!("3. Delete user");
        println!("4. Add device");
        println!("5. Delete device");
        println!("6. List user");
        println!("7. List device");
        println!("8. Exit");

        let mut choice = String::new();
        io::stdin().read_line(&mut choice).unwrap();

        match choice.trim() {
            "1" => create_database(db_path),
            "2" => add_user(db_path),
            "3" => delete_user(db_path),
            "4" => add_device(db_path),
            "5" => delete_device(db_path),
            "6" => list_user(db_path),
            "7" => list_device(db_path),
            "8" => break,
            _ => println!("Invalid choice"),
        }
    }
}

fn create_database(db_path: &str) {
    let connection = Connection::open(db_path).unwrap();

    let create_users = connection.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT NOT NULL, password TEXT NOT NULL, token TEXT, valid TIMESTAMP)", ());
    if create_users.is_err() {
        println!(
            "Failed to create users table: {}",
            create_users.err().unwrap()
        );
        return;
    }

    let create_devices = connection.execute("CREATE TABLE IF NOT EXISTS devices (id INTEGER PRIMARY KEY, user_id INTEGER, device_name TEXT NOT NULL, uuid TEXT NOT NULL, FOREIGN KEY(user_id) REFERENCES users(id))", ());
    if create_devices.is_err() {
        println!(
            "Failed to create devices table: {}",
            create_devices.err().unwrap()
        );
        return;
    }
    println!("Databases created!");
}

fn add_user(db_path: &str) {
    let mut username = String::new();
    let mut password = String::new();

    println!("Enter username:");
    io::stdin().read_line(&mut username).unwrap();

    println!("Enter password:");
    io::stdin().read_line(&mut password).unwrap();

    let hashed_password = bcrypt::hash(password.trim(), bcrypt::DEFAULT_COST).unwrap();
    let connection = Connection::open(db_path).unwrap();
    let res = connection
        .execute(
            "INSERT INTO users (username, password) VALUES (?1, ?2)",
            &[&username.trim(), &hashed_password.as_str()],
        )
        .unwrap();
    if res == 1 {
        println!("User added!");
    } else {
        println!("Failed to add user!");
    }
}

fn delete_user(db_path: &str) {
    let mut uid = String::new();
    let mut username = String::new();

    let connection = Connection::open(db_path).unwrap();

    println!("Enter user ID: (Leave blank to enter username)");
    io::stdin().read_line(&mut uid).unwrap();

    if uid.trim().is_empty() {
        println!("Enter username:");
        io::stdin().read_line(&mut username).unwrap();
        // Find the user ID
        let mut statement = connection
            .prepare("SELECT id FROM users WHERE username = ?1")
            .unwrap();
        let mut rows = statement.query(&[&username.trim()]).unwrap();
        let row = rows.next().unwrap().unwrap();
        uid = row.get(0).unwrap();
    }

    // Delete any devices associated with the user
    let res = connection
        .execute("DELETE FROM devices WHERE user_id = ?1", &[&uid.trim()])
        .unwrap();
    if res == 1 {
        println!("Devices deleted!");
    } else {
        println!("Failed to delete devices!");
    }

    let res = connection
        .execute("DELETE FROM users WHERE id = ?1", &[&uid.trim()])
        .unwrap();
    if res == 1 {
        println!("User deleted!");
    } else {
        println!("Failed to delete user!");
    }
}

fn add_device(db_path: &str) {
    let mut uid = String::new();
    let mut device_uuid = String::new();
    let mut device_name = String::new();

    println!("Enter user ID:");
    io::stdin().read_line(&mut uid).unwrap();

    println!("Enter device UUID:");
    io::stdin().read_line(&mut device_uuid).unwrap();

    println!("Enter device name:");
    io::stdin().read_line(&mut device_name).unwrap();

    let connection = Connection::open(db_path).unwrap();
    let res = connection.execute("INSERT INTO devices (user_id, device_name, uuid) VALUES (?1, ?2, ?3)", &[&uid.trim(), &device_name.trim(), &device_uuid.trim()]).unwrap();

    if res == 1 {
        println!("Device added!");
    } else {
        println!("Failed to add device!");
    }
}

fn delete_device(db_path: &str) {
    let mut uid = String::new();
    let mut device_uuid = String::new();

    println!("Enter Device ID: (Leave blank to enter UUID)");
    io::stdin().read_line(&mut uid).unwrap();

    let connection = Connection::open(db_path).unwrap();

    if uid.trim().is_empty() {
        println!("Enter device UUID:");
        io::stdin().read_line(&mut device_uuid).unwrap();
        // Find the user ID
        let mut statement = connection
            .prepare("SELECT id FROM devices WHERE uuid = ?1")
            .unwrap();
        let mut rows = statement.query(&[&device_uuid.trim()]).unwrap();
        let row = rows.next().unwrap().unwrap();
        let int_uid: i32 = row.get(0).unwrap();
        uid = int_uid.to_string();
    }

    let res = connection
        .execute("DELETE FROM devices WHERE id = ?1", &[&uid.trim()])
        .unwrap();
    if res == 1 {
        println!("Device deleted!");
    } else {
        println!("Failed to delete device!");
    }
}

fn list_user(db_path: &str) {
    let connection = Connection::open(db_path).unwrap();
    let mut statement = connection.prepare("SELECT * FROM users").unwrap();
    let mut rows = statement.query(()).unwrap();
    while let Some(row) = rows.next().unwrap() {
        let id: i32 = row.get(0).unwrap();
        let username: String = row.get(1).unwrap();
        println!("ID: {}, Username: {}", id, username);
    }
    println!("End of list");
}

fn list_device(db_path: &str) {
    let connection = Connection::open(db_path).unwrap();
    // Display the user ID and username and then list the devices for that user

    let mut statement = connection.prepare("SELECT * FROM users").unwrap();
    let mut rows = statement.query(()).unwrap();

    while let Some(row) = rows.next().unwrap() {
        let id: i32 = row.get(0).unwrap();
        let username: String = row.get(1).unwrap();
        println!("ID: {}, Username: {}", id, username);
        let mut statement = connection
            .prepare("SELECT * FROM devices WHERE user_id = ?1")
            .unwrap();
        let mut rows = statement.query(&[&id]).unwrap();
        while let Some(row) = rows.next().unwrap() {
            let id: i32 = row.get(0).unwrap();
            let device_name: String = row.get(2).unwrap();
            let uuid: String = row.get(3).unwrap();
            println!(
                "\tID: {}, Device Name: {}, UUID: {}",
                id, device_name, uuid
            );
        }
    }

    println!("End of list");
}
