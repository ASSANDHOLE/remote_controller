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

#[derive(Clone, Deserialize)]
struct Config {
    device_uuid: String,
    server_path: String,
    use_media_control_app: bool,
    media_control_app_path: Option<String>,
    media_control_app_shell_prefix: String,
}

async fn connect_and_handle_messages(config: Config) {
    // Connect to the server
    let url = Url::parse(&config.server_path).expect("Failed to parse server path");
    let conn = connect_async(url).await;
    if conn.is_err() {
        eprintln!(
            "[{}]::Failed to connect to server.",
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S")
        );
        return;
    }
    let (ws_stream, _) = conn.unwrap();
    let (mut ws_tx, mut ws_rx) = ws_stream.split();

    // Send the device UUID to the server
    let uuid_message = Message::text(&config.device_uuid.clone());
    ws_tx.send(uuid_message).await.unwrap();

    // Handle incoming messages
    while let Some(result) = ws_rx.next().await {
        match result {
            Ok(msg) => {
                // Process the incoming message and generate a response
                let response = process_message(msg, &config).await;

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

fn press_key_get_result(code: u32) -> bool {
    simulate(&EventType::KeyPress(Key::Unknown(code))).is_ok()
        && simulate(&EventType::KeyRelease(Key::Unknown(code))).is_ok()
}

fn processing_audio_setting(action: &String, config: &Config) -> i32 {
    if config.use_media_control_app {
        if let Some(media_control_app_path) = &config.media_control_app_path {
            let output = exec_get_output(&format!(
                "exec {} {} {}",
                config.media_control_app_shell_prefix, media_control_app_path, action
            ));
            if let Some((suc, _)) = output {
                return suc;
            }
        }
    }

    return if match action.as_str() {
        "vol_up" => press_key_get_result(175),
        "vol_down" => press_key_get_result(174),
        "vol_mute" => press_key_get_result(173),
        "pause" => press_key_get_result(179),
        "next" => press_key_get_result(176),
        "prev" => press_key_get_result(177),
        _ => false,
    } {
        1
    } else {
        0
    };
}

fn exec_get_output(command: &String) -> Option<(i32, String)> {
    let mut args: Vec<&str> = command.split_whitespace().collect();

    // Remove `exec` from the args
    args.remove(0);

    if args.is_empty() {
        return None;
    }

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

    let output = Command::new(cmd).args(&args).output();

    if let Ok(output) = output {
        return if output.status.success() {
            Some((
                output.status.code().unwrap_or(0),
                String::from_utf8_lossy(&output.stdout).to_string(),
            ))
        } else {
            Some((
                output.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&output.stderr).to_string(),
            ))
        };
    }

    None
}

async fn process_message(msg: Message, config: &Config) -> Option<String> {
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
    /// action: [audio [vol_up, vol_down, vol_mute, pause, next, prev] | exec [...]]
    ///
    /// # Response format:
    ///
    /// For audio:
    ///   { transaction: str, status: bool }
    /// For exec:
    ///   { transaction: str, status: true, message: { success: bool, execution: bool, output: str } }
    ///   { transaction: str, status: false, message: { cause: str } }
    ///
    let msg_str = msg.to_text().unwrap_or("");
    if msg_str.is_empty() {
        return None;
    }
    // { transaction: str, action: str }
    // action: [audio [vol_up, vol_down, vol_mute, pulse, next_track, prev_track] | exec [...]]
    let json = serde_json::from_str(msg_str).unwrap_or(Value::Null);
    if json.is_null() {
        return None;
    }
    return if let Some(transaction) = json.get("transaction") {
        if let Some(action) = json.get("action") {
            // Get Operator by splitting the action string of the first space
            let action_str = action.as_str().unwrap_or("").trim();
            if action_str.is_empty() {
                return Some(serde_json::json!({"transaction": transaction, "status": false, "message": {"cause": "Action Not Found."}}).to_string());
            }
            let operator = action_str.split_whitespace().next().unwrap();
            match operator {
                "audio" => {
                    if let Some(action) = action_str.split_whitespace().nth(1) {
                        let processing_res = processing_audio_setting(&action.to_string(), &config);
                        return if processing_res == 0 {
                            Some(serde_json::json!({"transaction": transaction, "status": true}).to_string())
                        } else {
                            Some(serde_json::json!({"transaction": transaction, "status": true, "message": {"exit": processing_res}}).to_string())
                        }
                    }
                    Some(serde_json::json!({"transaction": transaction, "status": false}).to_string())
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
    let exe_path = env::current_exe().expect("Failed to get executable path");
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
        use_media_control_app: config
            .get("control")
            .expect("Failed to get control")
            .get("use_media_control_app")
            .expect("Failed to get use_media_control_app")
            .parse::<i32>()
            .expect("Failed to parse use_media_control_app")
            != 0,
        media_control_app_path: config
            .get("control")
            .expect("Failed to get control")
            .get("media_control_app_path")
            .map(|s| s.to_string()),
        media_control_app_shell_prefix: config
            .get("control")
            .expect("Failed to get control")
            .get("media_control_app_shell_prefix")
            .map(|s| s.to_string())
            .unwrap_or("".to_string()),
    };

    loop {
        connect_and_handle_messages(config.clone()).await;
        eprintln!(
            "[{}]::Connection lost. Attempting to reconnect...",
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S")
        );
        sleep(Duration::from_millis(100)).await; // Wait 0.1 seconds before attempting to reconnect
    }
}
