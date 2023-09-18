use std::collections::HashMap;
use std::env;
use std::process::Command;

use futures_util::{SinkExt, StreamExt};
use rdev::{simulate, EventType, Key};
use serde::Deserialize;
use serde_json::Value;
use tokio::time::{sleep, Duration};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::protocol::Message;
use url::Url;
use which::which;

const CONFIG_PATH: &str = "config.toml";

#[derive(Clone, Deserialize)]
struct Config {
    device_uuid: String,
    server_path: String,
}

async fn connect_and_handle_messages(config: Config) {
    // Connect to the server
    let url = Url::parse(&config.server_path).expect("Failed to parse server path");
    let conn = connect_async(url).await;
    if conn.is_err() {
        eprintln!("Failed to connect to server.");
        return;
    }
    let (ws_stream, _) = conn.unwrap();
    let (mut ws_tx, mut ws_rx) = ws_stream.split();

    // Send the device UUID to the server
    let uuid_message = Message::text(config.device_uuid);
    ws_tx.send(uuid_message).await.unwrap();

    // Handle incoming messages
    while let Some(result) = ws_rx.next().await {
        match result {
            Ok(msg) => {
                // Process the incoming message and generate a response
                let response = process_message(msg).await;

                // Send the response back to the server
                if let Some(response) = response {
                    let response = Message::text(response);
                    ws_tx.send(response).await.unwrap();
                } else {
                    return;
                }
            }
            Err(_) => {
                return;
            }
        }
    }
}

fn processing_audio_setting(action: &String) -> bool {
    match action.as_str() {
        "vol_up" => {
            simulate(&EventType::KeyPress(Key::Unknown(175))).unwrap();
            simulate(&EventType::KeyRelease(Key::Unknown(175))).unwrap();
        }
        "vol_down" => {
            simulate(&EventType::KeyPress(Key::Unknown(174))).unwrap();
            simulate(&EventType::KeyRelease(Key::Unknown(174))).unwrap();
        }
        "vol_mute" => {
            simulate(&EventType::KeyPress(Key::Unknown(181))).unwrap();
            simulate(&EventType::KeyRelease(Key::Unknown(181))).unwrap();
        }
        "pulse" => {
            simulate(&EventType::KeyPress(Key::Unknown(179))).unwrap();
            simulate(&EventType::KeyRelease(Key::Unknown(179))).unwrap();
        }
        "next_track" => {
            simulate(&EventType::KeyPress(Key::Unknown(176))).unwrap();
            simulate(&EventType::KeyRelease(Key::Unknown(176))).unwrap();
        }
        "prev_track" => {
            simulate(&EventType::KeyPress(Key::Unknown(177))).unwrap();
            simulate(&EventType::KeyRelease(Key::Unknown(177))).unwrap();
        }
        _ => {
            return false;
        }
    }
    true
}

fn exec_get_output(command: &String) -> Option<(bool, String)> {
    // TODO: debug
    println!("exec_get_output: {}", command);

    let mut args: Vec<&str> = command.split_whitespace().collect();

    // Remove `exec` from the args
    args.remove(0);

    let cmd = if cfg!(windows) && !command.contains("\\") && !command.contains("/") {
        // For Windows, if the command doesn't have a path, search using PATHEXT
        let mut found_cmd = None;

        // First, try without any extension
        if let Ok(full_path) = which(args[0]) {
            found_cmd = Some(full_path);
        } else if let Ok(pathext) = env::var("PATHEXT") {
            for ext in pathext.split(';') {
                let cmd_with_ext = format!("{}{}", args[0], ext);
                if let Ok(full_path) = which(&cmd_with_ext) {
                    found_cmd = Some(full_path);
                    break;
                }
            }
        }

        match found_cmd {
            Some(full_path) => {
                args.remove(0);
                full_path.to_string_lossy().to_string()
            }
            None => args.remove(0).to_string(),
        }
    } else if !command.contains("/") && !command.contains("\\") {
        // For non-Windows, if the command doesn't have a path, use `which` crate
        match which(args[0]) {
            Ok(full_path) => {
                args.remove(0);
                full_path.to_string_lossy().to_string()
            }
            Err(_) => args.remove(0).to_string(),
        }
    } else {
        args.remove(0).to_string()
    };

    // TODO: debug
    println!("actual_executing: {} {:?}", cmd, args);

    let output = Command::new(cmd)
        .args(&args)
        .output();

    if let Ok(output) = output {
        return if output.status.success() {
            Some((true, String::from_utf8_lossy(&output.stdout).to_string()))
        } else {
            Some((false, String::from_utf8_lossy(&output.stderr).to_string()))
        }
    }

    None
}

async fn process_message(msg: Message) -> Option<String> {
    /// Process the incoming message and generate a response
    ///
    /// # Arguments
    ///
    /// * `msg` - The incoming message
    ///
    /// # Returns
    ///
    /// * `Option<String>` - The response message, if any, in JSON format
    ///
    /// # Message format:
    ///
    /// { transaction: str, action: str }
    /// action: [audio [vol_up, vol_down, vol_mute, pulse, next_track, prev_track] | exec [...]]
    ///
    /// # Response format:
    ///
    /// For audio:
    ///   { transaction: str, status: bool }
    /// For exec:
    ///   { transaction: str, status: true, message: { success: bool, execution: bool, output: str } }
    ///   { transaction: str, status: false, message: { cause: str } }
    ///

    let msg_str = msg.to_text().unwrap();
    // { transaction: str, action: str }
    // action: [audio [vol_up, vol_down, vol_mute, pulse, next_track, prev_track] | exec [...]]
    let json: Value = serde_json::from_str(msg_str).unwrap();
    return if let Some(transaction) = json.get("transaction") {
        if let Some(action) = json.get("action") {
            // Get Operator by splitting the action string of the first space
            let action_str = action.as_str().unwrap().trim();
            let operator = action_str.split_whitespace().next().unwrap();
            match operator {
                "audio" => {
                    let action = action_str.split_whitespace().nth(1).unwrap();
                    if processing_audio_setting(&action.to_string()) {
                        Some(serde_json::json!({"transaction": transaction, "status": true}).to_string())
                    } else {
                        Some(serde_json::json!({"transaction": transaction, "status": false}).to_string())
                    }
                }
                "exec" => {
                    let output = exec_get_output(&action_str.to_string());
                    if let Some((suc, output)) = output {
                        Some(serde_json::json!({"transaction": transaction, "status": true, "message": {"success": true, "execution": suc, "output": output}}).to_string())
                    } else {
                        Some(serde_json::json!({"transaction": transaction, "status": true, "message": {"success": false}}).to_string())
                    }
                }
                _ => {
                    Some(serde_json::json!({"transaction": transaction, "status": false, "message": {"cause": "Invalid Operator."}}).to_string())
                }
            }
        } else {
            Some(serde_json::json!({"transaction": transaction, "status": false, "message": {"cause": "Action Not Found."}}).to_string())
        }
    } else {
        None
    };
}

#[tokio::main]
async fn main() {
    let exe_path = std::env::current_exe().expect("Failed to get executable path");
    let exe_dir = exe_path
        .parent()
        .expect("Failed to get directory of executable");
    let config_path = exe_dir.join("config.toml");
    let contents = std::fs::read_to_string(config_path).expect("Failed to read config file");
    let config: HashMap<String, HashMap<String, String>> =
        toml::from_str(&contents).expect("Failed to parse config file");
    let config = Config {
        device_uuid: config
            .get("device")
            .expect("Failed to get device")
            .get("uuid")
            .expect("Failed to get device UUID")
            .to_string(),
        server_path: config
            .get("server")
            .expect("Failed to get server")
            .get("path")
            .expect("Failed to get server path")
            .to_string(),
    };

    loop {
        connect_and_handle_messages(config.clone()).await;
        eprintln!("Connection lost. Attempting to reconnect...");
        sleep(Duration::from_secs(5)).await; // Wait 5 seconds before attempting to reconnect
    }
}
