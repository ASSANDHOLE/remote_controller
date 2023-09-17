use chrono::{DateTime, NaiveDateTime};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use lazy_static::lazy_static;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use warp::Filter;

const SECRET_KEY: &str = "super_secret_key";

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

#[derive(Serialize)]
struct Device {
    id: i32,
    device_name: String,
    device_status: i32,
    uuid: String,
}

struct Action {
    action_type: String,
    device_uuid: String,
}

struct ExecResult {
    status: i32,
    message: Option<String>,
    data: Option<String>,
}

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

async fn login(user: UserInput) -> Result<impl warp::Reply, warp::Rejection> {
    let connection = get_db_connection();

    let mut stmt = connection
        .prepare("SELECT id, password FROM users WHERE username = ?1")
        .unwrap();
    let user_data: Result<(i32, String), _> =
        stmt.query_row(&[&user.username], |row| Ok((row.get(0)?, row.get(1)?)));

    if let Ok((user_id, stored_password)) = user_data {
        if bcrypt::verify(&user.password.trim(), &stored_password).is_ok() {
            // Generate JWT
            let expiration =
                (chrono::Utc::now() + COOKIE_VALID_DURATION.clone()).timestamp() as usize;
            let claims = Claims {
                sub: user_id.to_string(),
                exp: expiration,
            };
            let token = encode(
                &Header::default(),
                &claims,
                &EncodingKey::from_secret(SECRET_KEY.as_ref()),
            )
            .unwrap();

            // Store the token in the database with the expiration time
            connection
                .execute(
                    "UPDATE users SET token = ?1, valid = ?2 WHERE id = ?3",
                    (&token, &get_utc_timestamp_str(expiration as i64), &user_id),
                )
                .unwrap();

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
    }

    // Construct the error response
    Ok(warp::http::Response::builder()
        .status(warp::http::StatusCode::FORBIDDEN)
        .body("Invalid credentials."))
}

fn verify_auth(token: String) -> Result<i32, warp::Rejection> {
    let validation = Validation::default();
    match decode::<Claims>(
        &token,
        &DecodingKey::from_secret(SECRET_KEY.as_ref()),
        &validation,
    ) {
        Ok(token_data) => {
            let user_id: i32 = token_data.claims.sub.parse().unwrap_or(0);
            let connection = get_db_connection();

            // Validate token from DB
            let mut stmt = connection
                .prepare("SELECT token, valid FROM users WHERE id = ?1")
                .unwrap();
            let db_data: Result<(String, String), _> =
                stmt.query_row(&[&user_id], |row| Ok((row.get(0)?, row.get(1)?)));

            if let Ok((db_token, valid_until)) = db_data {
                return if &db_token == &token
                    && chrono::Utc::now().timestamp() <= get_utc_timestamp(valid_until.as_str())
                {
                    Ok(user_id)
                } else if &db_token == &token {
                    Err(warp::reject::custom(InvalidParameter {
                        message: "Token expired".to_string(),
                    }))
                } else {
                    Err(warp::reject::custom(InvalidParameter {
                        message: "Invalid token".to_string(),
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

async fn list_devices(cookie: String) -> Result<impl warp::Reply, warp::Rejection> {
    if let Some(token) = extract_token_from_cookie(cookie.as_str()) {
        return match verify_auth(token) {
            Ok(user_id) => {
                let connection = get_db_connection();

                // Fetch devices for the user
                let devices: Vec<Device> = connection
                    .prepare("SELECT id, device_name, device_status, uuid FROM devices WHERE user_id = ?1")
                    .unwrap()
                    .query_map(&[&user_id], |row| {
                        Ok(Device {
                            id: row.get(0)?,
                            device_name: row.get(1)?,
                            device_status: row.get(2)?,
                            uuid: row.get(3)?,
                        })
                    })
                    .unwrap()
                    .filter_map(Result::ok)
                    .collect();

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

async fn control_device(action: Action) -> ExecResult {
    // TODO: Implement this function

    match action.action_type.parse::<i32>() {
        Ok(_) => ExecResult {
            status: 0,
            message: Some(action.device_uuid),
            data: None,
        },
        Err(_) => ExecResult {
            status: 0,
            message: None,
            data: Some(action.action_type),
        },
    }
}

async fn audio_control(cookie: String, query_params: HashMap<String, String>, action_map: HashMap<String, String>) -> Result<impl warp::Reply, warp::Rejection> {
    let device_uuid = match query_params.get("device_uuid") {
        Some(uuid) => uuid.trim().to_string(),
        None => return Ok(warp::http::Response::builder()
            .status(warp::http::StatusCode::BAD_REQUEST)
            .body("Missing device_uuid.".to_string()))
    };
    let action = match action_map.get("action") {
        Some(action) => action.trim().to_string(),
        None => return Ok(warp::http::Response::builder()
            .status(warp::http::StatusCode::BAD_REQUEST)
            .body("Missing action.".to_string()))
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
            // Control the device
            let result = control_device(Action {
                action_type: action,
                device_uuid,
            }).await;

            // Construct the response
            if result.status == 0 {
                Ok(warp::http::Response::builder()
                    .status(warp::http::StatusCode::OK)
                    .body(result.data.unwrap_or("".to_string())))
            } else {
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
    let past_time = get_utc_timestamp_str(
        (chrono::Utc::now() - chrono::Duration::hours(2))
            .naive_utc()
            .timestamp(),
    );
    connection
        .execute(
            "UPDATE users SET valid = ?1 WHERE token = ?2",
            (&past_time, &token),
        )
        .unwrap();

    Ok(warp::http::Response::builder()
        .status(warp::http::StatusCode::OK)
        .header("set-cookie", "token=; HttpOnly; Path=/; Max-Age=0")
        .body("Logged out."))
}

#[tokio::main]
async fn main() {
    let login_route = warp::path("login")
        .and(warp::post())
        .and(warp::body::json())
        .and_then(login);

    let devices_route = warp::path("devices")
        .and(warp::get())
        .and(warp::header("cookie"))
        .and_then(list_devices);

    let logout_route = warp::path("logout")
        .and(warp::post())
        .and(warp::header("cookie"))
        .and_then(logout);

    let audio_control_route = warp::path("device")
        .and(warp::path("audio"))
        .and(warp::post())  // Assuming you want to use GET; if not, change this to .post() or .put() as required
        .and(warp::header("cookie"))
        .and(warp::query::<HashMap<String, String>>())  // This will parse the device_uuid from the query parameters
        .and(warp::body::json())  // This will parse the action from the JSON body
        .and_then(audio_control);


    let html_dir_route = warp::fs::dir(HTML_DIR_PATH.as_str());

    let routes = login_route
        .or(devices_route)
        .or(logout_route)
        .or(audio_control_route)
        .or(html_dir_route);

    warp::serve(routes).run(([127, 0, 0, 1], 3030)).await;
}
