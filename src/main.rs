mod user;
mod singleton;
mod web;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use rocket::{routes, Route, Config, Request, Data, State};
use rocket::response::status::BadRequest;
use rocket::serde::{json::Json, Deserialize};
use std::error::Error;
use rocket::fairing::{Fairing, Info, Kind};
use rocket::figment::Figment;
use rocket::http;
use rocket::http::Method;
use rocket_cors::{AllowedHeaders, AllowedOrigins};
use std::collections::HashSet;
use rocket::fs::{FileServer, relative};
/*
fn main() -> Result<(), Box<dyn Error>> {
    let conn = Singleton::get_db_connection()?;
    Singleton::create_tables(&conn)?;

    // Register a new user
    let mut new_user = User::new(String::from("John Doe"), String::from("john@example.com"), String::from("password"));
    new_user.set_passwords_clair(vec![
        String::from("password1"),
        String::from("password2"),
        String::from("password3"),
    ]);

    new_user.chiffrement_passwords();
    println!("Encrypted passwords: {:?}", new_user.get_passwords_chiffre());

    new_user.saveUsers(&conn)?;
    new_user.savePasswords(&conn)?;

    // Login an existing user
    let email = "john@example.com";
    let password = "password"; // Example password for demonstration

    match User::login(&conn, email, password)? {
        Some(mut loaded_user) => {
            println!("Login successful for user: {}", loaded_user.name);
            loaded_user.dechiffrement_passwords();
            println!("Decrypted passwords: {:?}", loaded_user.get_passwords_clair());
        },
        None => {
            println!("Login failed: User not found or invalid credentials.");
        }
    }

    Ok(())
}
*/
#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
struct LoginRequest {
    email: String,
    password: String,
}

#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
struct RegisterRequest {
    name: String,
    email: String,
    password: String,
}

type SessionMap = Arc<Mutex<HashMap<String, i32>>>;

struct SessionFairing;

#[rocket::async_trait]
impl Fairing for SessionFairing {
    fn info(&self) -> Info {
        Info {
            name: "Session Manager",
            kind: Kind::Request,
        }
    }

    async fn on_request(&self, request: &mut Request<'_>, _: &mut Data<'_>) {
        if let Some(cookie) = request.cookies().get("session_token") {
            let token = cookie.value().to_string();
            let sessions = request.guard::<&State<SessionMap>>().await.unwrap();
            let sessions = sessions.lock().unwrap();

            if let Some(user_id) = sessions.get(&token) {
                request.local_cache(|| *user_id);
            }
        }
    }
}
#[rocket::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Initialize the database connection and create tables
    let conn = singleton::Singleton::get_db_connection()?;
    singleton::Singleton::create_tables(&conn)?;

    // Create a shared session map
    let session_map: SessionMap = Arc::new(Mutex::new(HashMap::new()));

    // Configure Rocket with the desired port
    let figment = Figment::from(Config::default())
        .merge(("port", 8080));  // Change the port here

    let allowed_origins = AllowedOrigins::some_exact(&["http://localhost:8080"]);

    let cors = rocket_cors::CorsOptions {
        allowed_origins,
        allowed_methods: vec![Method::Get, Method::Post, Method::Options]
            .into_iter()
            .map(From::from)
            .collect(),
        allowed_headers: AllowedHeaders::all(),
        allow_credentials: true,
        ..Default::default()
    }.to_cors()?;


    // Launch Rocket with the custom configuration, routes, and session management
    rocket::custom(figment)
        .mount("/api", routes![
            web::register_user,
            web::login_user,
            web::save_passwords,
            web::decrypt_passwords,
            web::generate_password
        ])
        .mount("/", FileServer::from("../Frontend"))
        .manage(session_map)
        .attach(SessionFairing)
        .attach(cors)
        .launch()
        .await?;

    Ok(())
}
