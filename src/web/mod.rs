use rocket::{Route, response::status::BadRequest, State};
use rocket::response::status;
use rocket::serde::{Deserialize, Serialize, json::Json};
use rusqlite::{params, Connection, Result};
use crate::{user::User, singleton::Singleton};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use rocket::http::Cookie;
use rocket::http::CookieJar;
use rocket::response::status::Unauthorized;
use rocket::fs::NamedFile;
use std::path::{Path, PathBuf};
type SessionMap = Arc<Mutex<HashMap<String, i32>>>;

#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct LoginRequest {
    email: String,
    password: String,
}

#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct RegisterRequest {
    name: String,
    email: String,
    password: String,
}

#[derive(Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
struct ApiResponse<T> {
    success: bool,
    data: Option<T>,
    error: Option<String>,
    session_token: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct SavePasswordsRequest {
    passwords: Vec<String>,
}

#[rocket::post("/register", data = "<register_request>")]
pub async fn register_user(
    register_request: Json<RegisterRequest>,
    cookies: &CookieJar<'_>,
    sessions: &State<SessionMap>
) -> Result<Json<ApiResponse<()>>, BadRequest<String>> {
    let mut new_user = User::new(register_request.name.clone(), register_request.email.clone(), register_request.password.clone());
    new_user.chiffrement_passwords();
    new_user.saveUsers();
    new_user.savePasswords();

    // Generate a session token
    let session_token = format!("session_{}", new_user.id);
    cookies.add(Cookie::new("session_token", session_token.clone()));

    // Store the session in the shared state
    let mut sessions = sessions.lock().unwrap();
    sessions.insert(session_token.clone(), new_user.id);

    Ok(Json(ApiResponse {
        success: true,
        data: None,
        error: None,
        session_token: Some(session_token),
    }))
}

#[rocket::post("/login", data = "<login_request>")]
pub async fn login_user(
    login_request: Json<LoginRequest>,
    cookies: &CookieJar<'_>,
    sessions: &State<SessionMap>
) -> Result<Json<ApiResponse<String>>, status::BadRequest<String>> {
    match User::login(&login_request.email, &login_request.password) {
        Ok(Some(mut loaded_user)) => {
            loaded_user.dechiffrement_passwords();

            // Generate a session token
            let session_token = format!("session_{}", loaded_user.id);
            cookies.add(Cookie::new("session_token", session_token.clone()));

            // Store the session in the shared state
            let mut sessions = sessions.lock().unwrap();
            sessions.insert(session_token.clone(), loaded_user.id);

            Ok(Json(ApiResponse {
                success: true,
                data: Some(format!("Login successful for {}", loaded_user.name)),
                error: None,
                session_token: Some(session_token),
            }))
        },
        Ok(None) => {
            Err(status::BadRequest("Invalid email or password".to_string()))
        },
        Err(_) => {
            Err(status::BadRequest("An error occurred while trying to log in".to_string()))
        },
    }
}

#[rocket::post("/save-passwords", data = "<save_passwords_request>")]
pub async fn save_passwords(
    cookies: &CookieJar<'_>,
    sessions: &State<SessionMap>,
    save_passwords_request: Json<SavePasswordsRequest>,
) -> Result<Json<ApiResponse<()>>, status::Unauthorized<String>> {
    let session_token = cookies.get("session_token").map(|c| c.value().to_string());

    if let Some(token) = session_token {
        let sessions = sessions.lock().unwrap();
        if let Some(&user_id) = sessions.get(&token) {
            // Charger l'utilisateur à partir de l'ID de l'utilisateur
            match User::find_by_id(user_id) {
                Ok(Some(mut user)) => {
                    user.set_passwords_clair(save_passwords_request.passwords.clone());
                    user.chiffrement_passwords();
                    if let Err(e) = user.savePasswords() {
                        return Err(status::Unauthorized(format!("Failed to save passwords: {}", e)));
                    }

                    return Ok(Json(ApiResponse {
                        success: true,
                        data: None,
                        error: None,
                        session_token: None,
                    }));
                }
                Ok(None) => {
                    return Err(status::Unauthorized("User not found".to_string()));
                }
                Err(e) => {
                    return Err(status::Unauthorized(format!("Database error: {}", e)));
                }
            }
        }
    }

    Err(status::Unauthorized("You must be logged in to access this resource".to_string()))
}


#[rocket::post("/decrypt-passwords")]
pub async fn decrypt_passwords(
    cookies: &CookieJar<'_>,
    sessions: &State<SessionMap>
) -> Result<Json<ApiResponse<Vec<String>>>, status::Unauthorized<String>> {
    let session_token = cookies.get("session_token").map(|c| c.value().to_string());

    if let Some(token) = session_token {
        let sessions = sessions.lock().unwrap();
        if let Some(&user_id) = sessions.get(&token) {
            // Charger l'utilisateur à partir de l'ID de l'utilisateur
            match User::find_by_id(user_id) {
                Ok(Some(mut user)) => {
                    // Déchiffrer les mots de passe
                    user.dechiffrement_passwords();
                    let decrypted_passwords = user.get_passwords_clair().clone();

                    return Ok(Json(ApiResponse {
                        success: true,
                        data: Some(decrypted_passwords),
                        error: None,
                        session_token: None,
                    }));
                }
                Ok(None) => {
                    return Err(status::Unauthorized("User not found".to_string()));
                }
                Err(e) => {
                    return Err(status::Unauthorized(format!("Database error: {}", e)));
                }
            }
        }
    }

    Err(status::Unauthorized("You must be logged in to access this resource".to_string()))
}

#[rocket::post("/generate-password")]
pub async fn generate_password(
    cookies: &CookieJar<'_>,
    sessions: &State<SessionMap>
) -> Result<Json<ApiResponse<String>>, status::Unauthorized<String>> {
    let session_token = cookies.get("session_token").map(|c| c.value().to_string());

    if let Some(token) = session_token {
        let sessions = sessions.lock().unwrap();
        if let Some(&user_id) = sessions.get(&token) {
            // Charger l'utilisateur à partir de l'ID de l'utilisateur
            match User::find_by_id(user_id) {
                Ok(Some(mut user)) => {
                    let password = user.generate_password();
                    return Ok(Json(ApiResponse {
                        success: true,
                        data: Some(password),
                        error: None,
                        session_token: None,
                    }));
                }
                Ok(None) => {
                    return Err(status::Unauthorized("User not found".to_string()));
                }
                Err(e) => {
                    return Err(status::Unauthorized(format!("Database error: {}", e)));
                }
            }
        }
    }
    Err(status::Unauthorized("You must be logged in to access this resource".to_string()))
}