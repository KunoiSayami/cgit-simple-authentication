#![feature(array_methods)]
/*
 ** Copyright (C) 2021 KunoiSayami
 **
 ** This file is part of cgit-simple-authentication and is released under
 ** the AGPL v3 License: https://www.gnu.org/licenses/agpl-3.0.txt
 **
 ** This program is free software: you can redistribute it and/or modify
 ** it under the terms of the GNU Affero General Public License as published by
 ** the Free Software Foundation, either version 3 of the License, or
 ** any later version.
 **
 ** This program is distributed in the hope that it will be useful,
 ** but WITHOUT ANY WARRANTY; without even the implied warranty of
 ** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 ** GNU Affero General Public License for more details.
 **
 ** You should have received a copy of the GNU Affero General Public License
 ** along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

mod database;
mod datastructures;

use crate::datastructures::{Config, FormData, get_current_timestamp, Cookie, rand_int, rand_str};
use anyhow::Result;
use clap::{App, Arg, ArgMatches, SubCommand};
use handlebars::Handlebars;
use log4rs::append::file::FileAppender;
use log4rs::config::{Appender, Root};
use log4rs::encode::pattern::PatternEncoder;
use redis::AsyncCommands;
use serde::Serialize;
use sqlx::Connection;
use std::env;
use std::io::{stdin, Read};
use std::result::Result::Ok;
use tokio_stream::StreamExt as _;
use argon2::{
    password_hash::{PasswordHash},
};

const COOKIE_LENGTH: usize = 45;


// Processing the `authenticate-cookie` called by cgit.
async fn cmd_authenticate_cookie(matches: &ArgMatches<'_>, cfg: Config) -> Result<bool> {
    let cookies = matches.value_of("http-cookie").unwrap_or("");

    let mut bypass = false;

    if cfg.bypass_root && matches.value_of("current-url").unwrap_or("").eq("/") {
        bypass = true;
    }

    if bypass {
        return Ok(true);
    }

    if cookies.is_empty() {
        return Ok(false);
    }

    let redis_conn = redis::Client::open("redis://127.0.0.1/")?;
    let mut conn = redis_conn.get_async_connection().await?;

    if let Ok(Some(cookie)) = Cookie::load_from_request(cookies) {
        if let Ok(r) = conn.get::<_, String>(format!("cgit_auth_{}", cookie.get_key())).await{
            if cookie.eq_body(r.as_str()) {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

async fn cmd_init(cfg: Config) -> Result<()> {
    log::trace!("{}", cfg.get_database_location());
    let loc = std::path::Path::new(cfg.get_database_location());
    if !loc.exists() {
        std::fs::File::create(loc)?;
    }

    let mut conn = sqlx::SqliteConnection::connect(cfg.get_database_location()).await?;

    let rows = sqlx::query(r#"SELECT name FROM sqlite_master WHERE type='table' AND name=?"#)
        .bind("auth_meta")
        .fetch_all(&mut conn)
        .await?;

    if rows.is_empty() {
        sqlx::query(database::current::CREATE_TABLES)
            .execute(&mut conn)
            .await?;
        log::info!("Initialize the database successfully");
    }

    Ok(())
}

async fn verify_login(cfg: &Config, data: &FormData) -> Result<bool> {
    // TODO: use timestamp to mark file diff
    //       or copy in init process
    let database_file_name = std::path::Path::new(datastructures::CACHE_DIR).join(
        std::path::Path::new(cfg.get_database_location())
            .file_name()
            .unwrap(),
    );
    std::fs::copy(cfg.get_database_location(), database_file_name.clone())?;
    let mut conn = sqlx::SqliteConnection::connect(database_file_name.to_str().unwrap()).await?;
    let (passwd_hash,) = sqlx::query_as::<_, (String, )>(r#"SELECT "password" FROM "accounts" WHERE "user" = ?"#)
        .bind(data.get_user())
        .fetch_one(&mut conn)
        .await?;
    let parsed_hash = PasswordHash::new(passwd_hash.as_str()).unwrap();
    Ok(data.verify_password(&parsed_hash))
}

// Processing the `authenticate-post` called by cgit.
async fn cmd_authenticate_post(matches: &ArgMatches<'_>, cfg: Config) -> Result<()> {
    // Read stdin from upstream.
    let mut buffer = String::new();
    stdin().read_to_string(&mut buffer)?;
    log::debug!("{}", buffer);
    let data = datastructures::FormData::from(buffer);
    // Parsing user posted form.

    let ret = verify_login(&cfg, &data).await;

    if let Err(ref e) = ret {
        log::error!("{:?}", e)
    }

    if ret.unwrap_or(false) {
        let key = format!("{}_{}", get_current_timestamp(), rand_int());
        let value = rand_str(COOKIE_LENGTH);

        let redis_conn = redis::Client::open("redis://127.0.0.1/")?;
        let mut conn = redis_conn.get_async_connection().await?;
        conn.set_ex::<_, _, String>(
            format!("cgit_auth_{}", key),
            &value,
            cfg.cookie_ttl as usize,
        )
        .await?;

        let cookie_value = base64::encode(format!("{};{}", key, value));

        let is_secure = matches
            .value_of("https")
            .map_or(false, |x| matches!(x, "yes" | "on" | "1"));
        let domain = matches.value_of("http-host").unwrap_or("*");
        let location = matches.value_of("http-referer").unwrap_or("/");
        let cookie_suffix = if is_secure { "; secure" } else { "" };
        println!("Status: 302 Found");
        println!("Cache-Control: no-cache, no-store");
        println!("Location: {}", location);
        println!(
            "Set-Cookie: cgit_auth={}; Domain={}; Max-Age={}; HttpOnly{}",
            cookie_value, domain, cfg.cookie_ttl, cookie_suffix
        );
    } else {
        println!("Status: 403 Forbidden");
        println!("Cache-Control: no-cache, no-store");
    }

    Ok(())
}

#[derive(Serialize)]
pub struct Meta<'a> {
    action: &'a str,
    redirect: &'a str,
    //custom_warning: &'a str,
}


// Processing the `body` called by cgit.
async fn cmd_body(matches: &ArgMatches<'_>, cfg: Config) {
    let source = include_str!("authentication_page.html");
    let handlebars = Handlebars::new();
    let meta = Meta {
        action: matches.value_of("login-url").unwrap_or(""),
        redirect: matches.value_of("current-url").unwrap_or(""),
        //custom_warning: cfg.get_secret_warning()
    };
    handlebars
        .render_template_to_write(source, &meta, std::io::stdout())
        .unwrap();
}

async fn cmd_add_user(matches: &ArgMatches<'_>, cfg: Config) -> Result<()> {
    let user = matches.value_of("user").unwrap_or("");
    let passwd = matches.value_of("password").unwrap_or("").to_string();
    if user.is_empty() || passwd.is_empty() {
        return Err(anyhow::Error::msg("Invalid user or password"));
    }

    if user.len() > 20 {
        return Err(anyhow::Error::msg("Username length should less than 20"))
    }

    let mut conn = sqlx::SqliteConnection::connect(cfg.get_database_location()).await?;

    let items = sqlx::query(r#"SELECT 1 FROM "accounts" WHERE "user" = ? "#)
        .bind(user)
        .fetch_all(&mut conn)
        .await?;

    if !items.is_empty() {
        return Err(anyhow::Error::msg("User already exists!"));
    }

    sqlx::query(r#"INSERT INTO "accounts" ("user", "password") VALUES (?, ?) "#)
        .bind(user)
        .bind(FormData::get_string_argon2_hash(&passwd)?)
        .execute(&mut conn)
        .await?;
    println!("Insert {} to database", user);
    Ok(())
}

async fn cmd_list_user(cfg: Config) -> Result<()> {
    let mut conn = sqlx::SqliteConnection::connect(cfg.get_database_location()).await?;

    let (count,) = sqlx::query_as::<_, (i32,)>(r#"SELECT COUNT(*) FROM "accounts""#)
        .fetch_one(&mut conn)
        .await?;

    if count > 0 {
        let mut iter =
            sqlx::query_as::<_, (String,)>(r#"SELECT "user" FROM "accounts""#).fetch(&mut conn);

        println!(
            "There is {} user{} in database",
            count,
            if count > 1 { "s" } else { "" }
        );
        while let Some(Ok((row,))) = iter.next().await {
            println!("{}", row)
        }
    } else {
        println!("There is not user exists.")
    }

    Ok(())
}

async fn cmd_delete_user(matches: &ArgMatches<'_>, cfg: Config) -> Result<()> {
    let user = matches.value_of("user").unwrap_or("");
    if user.is_empty() {
        return Err(anyhow::Error::msg("Please input a valid username"))
    }

    let mut conn = sqlx::SqliteConnection::connect(cfg.get_database_location()).await?;

    let items = sqlx::query_as::<_, (i32,)>(r#"SELECT 1 FROM "accounts" WHERE "user" = ?"#)
        .bind(user)
        .fetch_all(&mut conn)
        .await?;

    if items.is_empty() {
        return Err(anyhow::Error::msg(format!("User {} not found", user)))
    }

    sqlx::query(r#"DELETE FROM "accounts" WHERE "user" = ?"#)
        .bind(user)
        .execute(&mut conn)
        .await?;

    println!("Delete {} from database", user);

    Ok(())
}

async fn async_main(arg_matches: ArgMatches<'_>, cfg: Config) -> Result<i32> {
    match arg_matches.subcommand() {
        ("authenticate-cookie", Some(matches)) => {
            if let Ok(should_pass) = cmd_authenticate_cookie(matches, cfg).await {
                if should_pass {
                    return Ok(1);
                }
            }
        }
        ("authenticate-post", Some(matches)) => {
            cmd_authenticate_post(matches, cfg).await?;
            println!();
        }
        ("body", Some(matches)) => {
            cmd_body(matches, cfg).await;
        }
        ("init", Some(_matches)) => {
            cmd_init(cfg).await?;
        }
        ("adduser", Some(matches)) => {
            cmd_add_user(matches, cfg).await?;
        }
        ("users", Some(_matches)) => {
            cmd_list_user(cfg).await?;
        }
        ("deluser", Some(matches)) => {
            cmd_delete_user(matches, cfg).await?;
        }
        _ => {}
    }
    Ok(0)
}

fn main() -> Result<()> {
    let logfile = FileAppender::builder()
        .encoder(Box::new(PatternEncoder::new(
            "{d(%Y-%m-%d %H:%M:%S)}- {h({l})} - {m}{n}",
        )))
        .build(option_env!("RUST_LOG_FILE").unwrap_or("/tmp/auth.log"))?;

    let config = log4rs::Config::builder()
        .appender(Appender::builder().build("logfile", Box::new(logfile)))
        .logger(log4rs::config::Logger::builder().build("sqlx::query", log::LevelFilter::Warn))
        .logger(
            log4rs::config::Logger::builder().build("handlebars::render", log::LevelFilter::Warn),
        )
        .logger(
            log4rs::config::Logger::builder().build("handlebars::context", log::LevelFilter::Warn),
        )
        .build(
            Root::builder()
                .appender("logfile")
                .build(log::LevelFilter::Debug),
        )?;

    log4rs::init_config(config)?;
    //simple_logging::log_to_file("/tmp/auth.log", log::LevelFilter::Debug)?;

    log::debug!(
        "{}",
        env::args()
            .enumerate()
            .map(|(nth, arg)| format!("[{}]={}", nth, arg))
            .collect::<Vec<String>>()
            .join(" ")
    );

    // Sub-arguments for each command, see cgi defines.
    let sub_args = &[
        Arg::with_name("http-cookie").required(true), // 2
        Arg::with_name("request-method").required(true),
        Arg::with_name("query-string").required(true),
        Arg::with_name("http-referer").required(true), // 5
        Arg::with_name("path-info").required(true),
        Arg::with_name("http-host").required(true),
        Arg::with_name("https").required(true),
        Arg::with_name("repo").required(true),
        Arg::with_name("page").required(true), // 10
        Arg::with_name("current-url").required(true),
        Arg::with_name("login-url").required(true),
    ];

    let matches = App::new("Simple Authentication Filter for cgit")
        .version(env!("CARGO_PKG_VERSION"))
        .subcommand(
            SubCommand::with_name("authenticate-cookie")
                .about("Processing authenticated cookie")
                .args(sub_args),
        )
        .subcommand(
            SubCommand::with_name("authenticate-post")
                .about("Processing posted username and password")
                .args(sub_args),
        )
        .subcommand(
            SubCommand::with_name("body")
                .about("Return the login form")
                .args(sub_args),
        )
        .subcommand(SubCommand::with_name("init").about("Init sqlite database"))
        .subcommand(SubCommand::with_name("users").about("List all register user in database"))
        .subcommand(
            SubCommand::with_name("adduser")
                .about("Add user to database")
                .arg(Arg::with_name("user").required(true))
                .arg(Arg::with_name("password").required(true)),
        )
        .subcommand(
            SubCommand::with_name("deluser")
                .about("Delete user from database")
                .arg(Arg::with_name("user").required(true))
        )
        .get_matches();

    // Load filter configurations
    let cfg = Config::new();

    let ret = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async_main(matches, cfg))?;
    if ret == 1 {
        std::process::exit(1);
    }

    Ok(())
}

mod test {
    const PASSWORD: &str = "hunter2";
    const ARGON2_HASH: &str = "$argon2id$v=19$m=4096,t=3,p=1$szYDnoQSVPmXq+RD2LneBw$fRETH//iCQuIX+SgjYPdZ9iIbM8gEy9fBjTJ/KFFJNM";
    use argon2::{
        password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
        Argon2
    };
    use rand_core::OsRng;


    #[test]
    fn test_argon2() {
        let passwd = PASSWORD.as_bytes();
        let salt = SaltString::generate(&mut OsRng);

        let argon2 = Argon2::default();

        argon2.hash_password_simple(passwd, salt.as_ref()).unwrap();

    }

    #[test]
    fn test_argon2_verify() {
        let passwd = PASSWORD.as_bytes();
        let parsed_hash = PasswordHash::new(ARGON2_HASH).unwrap();
        let argon2 = Argon2::default();
        assert!(argon2.verify_password(passwd, &parsed_hash).is_ok())
    }
}

