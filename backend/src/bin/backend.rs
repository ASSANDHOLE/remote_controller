use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::result;

use chrono::{DateTime, NaiveDateTime};
use futures_util::{SinkExt, StreamExt, TryFutureExt};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use lazy_static::lazy_static;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, RwLock};
use tokio_stream::wrappers::UnboundedReceiverStream;
use uuid::Uuid;
use warp::ws::{Message, WebSocket};
use warp::Filter;

// const SECRET_KEY: &str = "super_secret_key";

lazy_static! {
    static ref CONFIG: HashMap<String, HashMap<String, String>> = {
        let exe_path = std::env::current_exe().expect("Failed to get executable path");
        let exe_dir = exe_path.parent().expect("Failed to get directory of executable");
        let config_path = exe_dir.join("config.toml");
        let contents = std::fs::read_to_string(config_path).expect("Failed to read config file");
        let config: HashMap<String, HashMap<String, String>> = toml::from_str(&contents).expect("Failed to parse config file");
        config.clone()
    };
    static ref DB_PATH: String = {
        let db_path = CONFIG.get("database").unwrap().get("path").expect("Failed to get database path");
        db_path.to_string()
    };
    static ref HTML_DIR_PATH: String = {
        let html_path = CONFIG.get("html").unwrap().get("dir_path").expect("Failed to get html dir path");
        html_path.to_string()
    };
    static ref COOKIE_VALID_DURATION: chrono::Duration = {
        let duration = CONFIG.get("cookie").unwrap().get("valid_duration").expect("Failed to get cookie valid duration");
        // D: days, H: hours, M: minutes, S: seconds
        let unit = duration.chars().last().unwrap();
        let duration = duration[..duration.len() - 1].parse::<i64>().expect("Failed to parse cookie valid duration");
        match unit {
            'D' => chrono::Duration::days(duration),
            'H' => chrono::Duration::hours(duration),
            'M' => chrono::Duration::minutes(duration),
            'S' => chrono::Duration::seconds(duration),
            _ => panic!("Invalid unit of cookie valid duration")
        }
    };
    static ref CHECK_TIMEOUT: i32 = {
        let timeout = CONFIG.get("device").unwrap().get("check_timeout").expect("Failed to get device check timeout");
        timeout.parse::<i32>().expect("Failed to parse device check timeout")
    };
    static ref QUEUE_SIZE: usize = {
        let size = CONFIG.get("device").unwrap().get("queue_size").expect("Failed to get device queue size");
        size.parse::<usize>().expect("Failed to parse device queue size")
    };
    static ref SECRET_KEY: String = {
        let secret_key = CONFIG.get("server").unwrap().get("secret_key").expect("Failed to get server secret key");
        secret_key.to_string()
    };
    static ref ENC_KEY: EncodingKey = {
        EncodingKey::from_base64_secret(SECRET_KEY.as_ref()).expect("Failed to get encoding key")
    };
    static ref DEC_KEY: DecodingKey = {
        DecodingKey::from_base64_secret(SECRET_KEY.as_ref()).expect("Failed to get decoding key")
    };
    static ref SERVE_ADDR: SocketAddr = {
        let serve_addr = CONFIG.get("server").unwrap().get("serve_addr").expect("Failed to get server serve address");
        serve_addr.parse::<SocketAddr>().expect("Failed to parse server serve address")
    };
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

#[derive(Debug)]
struct InvalidParameter {
    message: String,
}

impl warp::reject::Reject for InvalidParameter {}

#[derive(Deserialize)]
struct UserInput {
    username: String,
    password: String,
}

#[derive(Debug, Serialize)]
struct Device {
    id: i32,
    device_name: String,
    device_status: i32,
    uuid: String,
}

#[derive(Debug)]
struct ExecResult {
    status: i32, // 0: success, 1: failed, 2: timeout
    message: Option<String>,
    data: Option<String>,
}

#[derive(Debug)]
struct ClientData {
    status: bool,
    transaction: Option<String>,
    message: Option<String>,
}

struct BoundedClientDataQueue {
    queue: VecDeque<ClientData>,
    max_size: usize,
}

impl BoundedClientDataQueue {
    fn new() -> BoundedClientDataQueue {
        BoundedClientDataQueue {
            queue: VecDeque::with_capacity(*QUEUE_SIZE),
            max_size: *QUEUE_SIZE,
        }
    }

    fn push(&mut self, data: ClientData) {
        if self.queue.len() == self.max_size {
            self.queue.pop_front();
        }
        self.queue.push_back(data);
    }

    fn remove(&mut self, index: usize) {
        self.queue.remove(index);
    }

    fn get_with_transaction(&self, transaction: &String) -> Option<(usize, &ClientData)> {
        for (i, data) in self.queue.iter().enumerate() {
            if let Some(last_transaction) = &data.transaction {
                if last_transaction == transaction {
                    return Some((i, data));
                }
            }
        }
        None
    }
}

type Devices = std::sync::Arc<RwLock<HashMap<String, mpsc::UnboundedSender<Message>>>>;
type ClientDataWithQueue = std::sync::Arc<RwLock<HashMap<String, BoundedClientDataQueue>>>;

fn get_db_connection() -> Connection {
    Connection::open(DB_PATH.as_str()).unwrap()
}

fn get_utc_timestamp_str(time_stamp: i64) -> String {
    // YYYY-MM-DDTHH:MM:SSZ
    let dt = NaiveDateTime::from_timestamp_opt(time_stamp, 0).unwrap();
    dt.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

fn get_utc_timestamp(time_stamp_str: &str) -> i64 {
    let dt = DateTime::parse_from_rfc3339(time_stamp_str).unwrap();
    dt.timestamp()
}

fn remove_expired_tokens(user_id: i32, connection: &Connection) {
    // Remove expired tokens
    let past_time = get_utc_timestamp_str(chrono::Utc::now().naive_utc().timestamp());
    connection
        .execute(
            "DELETE FROM cookies WHERE user_id = ?1 AND valid < ?2",
            (&user_id, &past_time),
        )
        .unwrap();
}

async fn login(user: UserInput) -> Result<impl warp::Reply, warp::Rejection> {
    let connection = get_db_connection();

    let mut stmt = connection
        .prepare("SELECT id, password FROM users WHERE username = ?1")
        .unwrap();
    let user_data: Result<(i32, String), _> =
        stmt.query_row(&[&user.username], |row| Ok((row.get(0)?, row.get(1)?)));

    if let Ok((user_id, stored_password)) = user_data {
        if let Ok(result) = bcrypt::verify(&user.password.trim(), &stored_password) {
            if !result {
                return Ok(warp::http::Response::builder()
                    .status(warp::http::StatusCode::FORBIDDEN)
                    .body("Invalid credentials."));
            }
        }
        // Generate JWT
        let expiration = (chrono::Utc::now() + COOKIE_VALID_DURATION.clone()).timestamp() as usize;
        let claims = Claims {
            sub: user_id.to_string(),
            exp: expiration,
        };
        let token = encode(&Header::default(), &claims, &ENC_KEY).unwrap();

        // Store the token in the database with the expiration time
        connection
            .execute(
                "INSERT INTO cookies (token, valid, user_id) VALUES (?1, ?2, ?3)",
                (&token, &get_utc_timestamp_str(expiration as i64), &user_id),
            )
            .unwrap();

        remove_expired_tokens(user_id, &connection);

        // Create a response with the token as a cookie
        let header_value = format!(
            "token={}; HttpOnly; Path=/; Max-Age={}",
            token,
            COOKIE_VALID_DURATION.num_seconds()
        );
        return Ok(warp::http::Response::builder()
            .status(warp::http::StatusCode::OK)
            .header("set-cookie", header_value)
            .body("User authenticated."));
    }

    // Construct the error response
    Ok(warp::http::Response::builder()
        .status(warp::http::StatusCode::FORBIDDEN)
        .body("Invalid credentials."))
}

fn verify_auth(token: String) -> Result<i32, warp::Rejection> {
    let validation = Validation::default();
    match decode::<Claims>(&token, &DEC_KEY, &validation) {
        Ok(token_data) => {
            let user_id: i32 = token_data.claims.sub.parse().unwrap_or(0);
            let connection = get_db_connection();

            // Validate token from DB
            let mut stmt = connection
                .prepare("SELECT valid FROM cookies WHERE user_id = ?1 AND token = ?2")
                .unwrap();
            let db_data: Result<String, _> =
                stmt.query_row((&user_id, &token), |row| Ok(row.get(0)?));

            if let Ok(valid_until) = db_data {
                return if chrono::Utc::now().timestamp() <= get_utc_timestamp(valid_until.as_str())
                {
                    remove_expired_tokens(user_id, &connection);
                    Ok(user_id)
                } else {
                    Err(warp::reject::custom(InvalidParameter {
                        message: "Token expired".to_string(),
                    }))
                };
            }

            Err(warp::reject::custom(InvalidParameter {
                message: "Invalid token".to_string(),
            }))
        }
        Err(_) => Err(warp::reject::custom(InvalidParameter {
            message: "Invalid token".to_string(),
        })),
    }
}

fn extract_token_from_cookie(cookie_header: &str) -> Option<String> {
    let cookies: Vec<&str> = cookie_header.split(';').collect();

    for cookie in cookies {
        let parts: Vec<&str> = cookie.splitn(2, '=').collect();
        if parts.len() == 2 && parts[0].trim() == "token" {
            return Some(parts[1].trim().to_string());
        }
    }

    None
}

async fn list_devices(
    cookie: String,
    device_map: Devices,
) -> Result<impl warp::Reply, warp::Rejection> {
    if let Some(token) = extract_token_from_cookie(cookie.as_str()) {
        return match verify_auth(token) {
            Ok(user_id) => {
                let connection = get_db_connection();

                // Fetch devices for the user
                let mut devices: Vec<Device> = connection
                    .prepare("SELECT id, device_name, uuid FROM devices WHERE user_id = ?1")
                    .unwrap()
                    .query_map(&[&user_id], |row| {
                        Ok(Device {
                            id: row.get(0)?,
                            device_name: row.get(1)?,
                            device_status: 0,
                            uuid: row.get(2)?,
                        })
                    })
                    .unwrap()
                    .filter_map(Result::ok)
                    .collect();
                // Find the status of each device
                let device_data = device_map.read().await;
                for dev in devices.iter_mut() {
                    if let Some(_) = device_data.get(&dev.uuid) {
                        dev.device_status = 1;
                    }
                }
                Ok(warp::http::Response::builder()
                    .status(warp::http::StatusCode::OK)
                    .body(serde_json::to_string(&devices).unwrap()))
            }
            Err(rej) => Err(rej),
        };
    } else {
        Ok(warp::http::Response::builder()
            .status(warp::http::StatusCode::UNAUTHORIZED)
            .body("Invalid token.".to_string()))
    }
}

async fn handle_connection(
    ws: WebSocket,
    devices: Devices,
    client_data_with_queue: ClientDataWithQueue,
) {
    let (mut device_ws_tx, mut device_ws_rx) = ws.split();

    let mut device_uuid: String = String::new();

    if let Some(Ok(msg)) = device_ws_rx.next().await {
        if let Ok(duid) = msg.to_str() {
            device_uuid = duid.to_string();
            // Use an unbounded channel to handle buffering and flushing of messages
            // to the websocket...
            let (tx, rx) = mpsc::unbounded_channel();
            let mut rx = UnboundedReceiverStream::new(rx);

            tokio::task::spawn(async move {
                while let Some(message) = rx.next().await {
                    device_ws_tx
                        .send(message)
                        .unwrap_or_else(|_| {
                            return;
                        })
                        .await;
                }
            });

            // Save the sender in our list of connected devices.
            devices.write().await.insert(duid.to_string(), tx);
            client_data_with_queue
                .write()
                .await
                .insert(duid.to_string(), BoundedClientDataQueue::new());
        }
    }

    // Handle further messages from the device...
    while let Some(result) = device_ws_rx.next().await {
        let mut flag: bool = false;
        let mut x_json_obj: Option<serde_json::Map<String, serde_json::Value>> = None;
        let mut x_transaction_str: String = String::new();
        match result {
            Ok(msg) => {
                // To JSON
                let msg = if let Ok(s) = msg.to_str() { s } else { break };
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(msg) {
                    if let Some(json_obj) = json.as_object() {
                        if let Some(transaction) = json_obj.get("transaction") {
                            if let Some(transaction_str) = transaction.as_str() {
                                flag = true;
                                x_json_obj = Some(json_obj.clone());
                                x_transaction_str = transaction_str.to_string();
                            }
                        }
                    }
                }
                if flag {
                    let mut client_data = client_data_with_queue.write().await;
                    let data = client_data.get_mut(&device_uuid).unwrap();
                    let message = x_json_obj
                        .as_ref()
                        .unwrap()
                        .get("message")
                        .unwrap_or(&serde_json::Value::Null);
                    // Beautify the message with indentation of 4 spaces
                    let message_str = serde_json::to_string_pretty(message);
                    let message_str = if let Ok(s) = message_str {
                        Some(s)
                    } else {
                        None
                    };
                    data.push(ClientData {
                        status: x_json_obj
                            .as_ref()
                            .unwrap()
                            .get("status")
                            .unwrap_or(&serde_json::Value::Null)
                            .as_bool()
                            .unwrap_or(false),
                        transaction: Some(x_transaction_str),
                        message: message_str,
                    });
                }
            }

            Err(_) => {
                // eprintln!("websocket error for device {}: {}", device_uuid, e);
                break;
            }
        }
    }

    // When the device disconnects...
    devices.write().await.remove(&device_uuid);
    client_data_with_queue.write().await.remove(&device_uuid);
}

async fn check_last_exec_status(
    transaction: &String,
    device_uuid: &String,
    client_data_with_queue: ClientDataWithQueue,
) -> (bool, bool, Option<String>) {
    let mut flag = false;
    let mut status = false;
    let mut message: Option<String> = None;
    let start_time = chrono::Utc::now().timestamp();
    while chrono::Utc::now().timestamp() - start_time < *CHECK_TIMEOUT as i64 {
        if let Some(device_data) = client_data_with_queue.write().await.get_mut(device_uuid) {
            if let Some((id, data)) = device_data.get_with_transaction(transaction) {
                flag = true;
                status = data.status;
                message = data.message.clone();
                device_data.remove(id);
                break;
            }
        }

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    (flag, status, message)
}

async fn device_control(
    cookie: String,
    query_params: HashMap<String, String>,
    action_map: HashMap<String, String>,
    devices: Devices,
    client_data_with_queue: ClientDataWithQueue,
) -> Result<impl warp::Reply, warp::Rejection> {
    let device_uuid = match query_params.get("device_uuid") {
        Some(uuid) => uuid.trim().to_string(),
        None => {
            return Ok(warp::http::Response::builder()
                .status(warp::http::StatusCode::BAD_REQUEST)
                .body("Missing device_uuid.".to_string()))
        }
    };
    let action = match action_map.get("action") {
        Some(action) => action.trim().to_string(),
        None => {
            return Ok(warp::http::Response::builder()
                .status(warp::http::StatusCode::BAD_REQUEST)
                .body("Missing action.".to_string()))
        }
    };
    if let Some(token) = extract_token_from_cookie(cookie.as_str()) {
        let mut flag = false;
        match verify_auth(token) {
            Ok(user_id) => {
                let connection = get_db_connection();

                // Find if the device exists and belongs to the user
                let mut statement = connection
                    .prepare("SELECT id FROM devices WHERE uuid = ?1 AND user_id = ?2")
                    .unwrap();
                let db_data: Result<i32, _> =
                    statement.query_row((&device_uuid.trim(), &user_id), |row| Ok(row.get(0)?));

                if let Ok(_) = db_data {
                    flag = true;
                }
            }

            Err(rej) => return Err(rej),
        };
        if flag {
            let transaction = Uuid::new_v4().to_string();
            let mut device_data = devices.write().await;
            let device = device_data.get_mut(&device_uuid).unwrap();
            let mut send_error = false;
            device
                .send(Message::text(
                    serde_json::json!({
                        "transaction": transaction,
                        "action": action,
                    })
                    .to_string(),
                ))
                .unwrap_or_else(|_| {
                    send_error = true;
                });
            if send_error {
                return Ok(warp::http::Response::builder()
                    .status(warp::http::StatusCode::SERVICE_UNAVAILABLE)
                    .body("Cannot send message to device.".to_string()));
            }
            drop(device_data);
            let (f, s, m) =
                check_last_exec_status(&transaction, &device_uuid, client_data_with_queue.clone())
                    .await;
            let mut result = ExecResult {
                status: 0,
                message: None,
                data: None,
            };

            if !f {
                result.status = 2; // timeout
            } else if !s {
                result.status = 1; // failed
                result.message = m;
            } else {
                result.status = 0; // success
                result.data = m;
            }

            // Construct the response
            if result.status == 0 {
                Ok(warp::http::Response::builder()
                    .status(warp::http::StatusCode::OK)
                    .body(result.data.unwrap_or("".to_string())))
            } else {
                if let None = &result.message {
                    result.message = match result.status {
                        1 => Some("Failed to execute command.".to_string()),
                        2 => Some("Timeout.".to_string()),
                        _ => None,
                    }
                }
                Ok(warp::http::Response::builder()
                    .status(warp::http::StatusCode::SERVICE_UNAVAILABLE)
                    .body(result.message.unwrap_or("".to_string())))
            }
        } else {
            Ok(warp::http::Response::builder()
                .status(warp::http::StatusCode::NOT_FOUND)
                .body("Device not found.".to_string()))
        }
    } else {
        Ok(warp::http::Response::builder()
            .status(warp::http::StatusCode::UNAUTHORIZED)
            .body("Invalid token.".to_string()))
    }
}

async fn logout(cookie: String) -> Result<impl warp::Reply, warp::Rejection> {
    let token = extract_token_from_cookie(cookie.as_str()).unwrap();
    let connection = get_db_connection();

    // Invalidate token in DB by setting a past valid timestamp
    connection
        .execute("DELETE FROM cookies WHERE token = ?1", (&token,))
        .unwrap();

    Ok(warp::http::Response::builder()
        .status(warp::http::StatusCode::OK)
        .header("set-cookie", "token=; HttpOnly; Path=/; Max-Age=0")
        .body("Logged out."))
}

fn not_authenticated() -> impl Filter<Extract = (), Error = warp::Rejection> + Copy {
    warp::header::<String>("cookie")
        .and_then(|cookie: String| async move {
            if let Some(token) = extract_token_from_cookie(cookie.as_str()) {
                match verify_auth(token) {
                    Ok(_) => Err(warp::reject::custom(InvalidParameter {
                        message: "Already authenticated.".to_string(),
                    })),
                    Err(_) => Ok(()),
                }
            } else {
                Ok(())
            }
        })
        .untuple_one()
        .or_else(|rej: warp::Rejection| async move {
            if let Some(_) = rej.find::<InvalidParameter>() {
                Err(rej)
            } else {
                Ok(())
            }
        })
}

#[tokio::main]
async fn main() {
    let devices: Devices = std::sync::Arc::new(RwLock::new(HashMap::new()));
    let devices = warp::any().map(move || devices.clone());

    let client_data_with_queue: ClientDataWithQueue =
        std::sync::Arc::new(RwLock::new(HashMap::new()));
    let client_data_with_queue = warp::any().map(move || client_data_with_queue.clone());

    let login_route = warp::path("api")
        .and(warp::path("login"))
        .and(warp::post())
        .and(warp::body::json())
        .and_then(login);

    let devices_route = warp::path("api")
        .and(warp::path("ls_devices"))
        .and(warp::get())
        .and(warp::header("cookie"))
        .and(devices.clone())
        .and_then(list_devices);

    let logout_route = warp::path("api")
        .and(warp::path("logout"))
        .and(warp::post())
        .and(warp::header("cookie"))
        .and_then(logout);

    let device_control_route = warp::path("api")
        .and(warp::path("device"))
        .and(warp::post())
        .and(warp::header("cookie"))
        .and(warp::query::<HashMap<String, String>>())
        .and(warp::body::json())
        .and(devices.clone())
        .and(client_data_with_queue.clone())
        .and_then(device_control);

    let ws_route = warp::path("ws")
        .and(warp::ws())
        .and(devices)
        .and(client_data_with_queue)
        .map(move |ws: warp::ws::Ws, devices, cq| {
            ws.on_upgrade(move |socket| handle_connection(socket, devices, cq))
        });

    let ico_route = warp::path("favicon.ico").and(warp::fs::file(format!(
        "{}/favicon.ico",
        HTML_DIR_PATH.as_str()
    )));

    let resources_route = warp::path("resources").and(warp::fs::dir(format!(
        "{}/resources",
        HTML_DIR_PATH.as_str()
    )));

    let html_login_route = warp::get().and(warp::path("login.html")).and(
        not_authenticated()
            .and(warp::fs::file(format!(
                "{}/login.html",
                HTML_DIR_PATH.as_str()
            )))
            .or(warp::any()
                .map(|| warp::redirect::temporary(warp::http::Uri::from_static("/index.html")))),
    );

    let html_dir_route = warp::get().and(
        not_authenticated()
            .and(
                warp::any()
                    .map(|| warp::redirect::temporary(warp::http::Uri::from_static("/login.html"))),
            )
            .or(warp::fs::dir(HTML_DIR_PATH.as_str())),
    );

    let routes = login_route
        .or(devices_route)
        .or(logout_route)
        .or(device_control_route)
        .or(ws_route)
        .or(ico_route)
        .or(resources_route)
        .or(html_login_route)
        .or(html_dir_route);

    warp::serve(routes).run(SERVE_ADDR.clone()).await;
}
