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

use crate::datastructures::{Config, Cookie, FormData};
use anyhow::Result;
use argon2::password_hash::PasswordHash;
use clap::{App, Arg, ArgMatches, SubCommand};
use handlebars::Handlebars;
use log4rs::append::file::FileAppender;
use log4rs::config::{Appender, Root};
use log4rs::encode::pattern::PatternEncoder;
use redis::AsyncCommands;
use serde::Serialize;
use sqlx::sqlite::SqliteConnectOptions;
use sqlx::{ConnectOptions, Connection, SqliteConnection};
use std::env;
use std::io::{BufRead, Write};
use std::result::Result::Ok;
use std::str::FromStr;
use tempdir::TempDir;
use tokio_stream::StreamExt as _;


struct IOModule<R, W> {
    reader: R,
    writer: W,
}

impl<R: BufRead, W: Write> IOModule<R, W> {
    // Processing the `authenticate-post` called by cgit.
    async fn cmd_authenticate_post(&mut self, matches: &ArgMatches<'_>, cfg: Config) -> Result<()> {
        // Read stdin from upstream.
        let mut buffer = String::new();
        // TODO: override it that can test function from cargo test
        self.reader.read_to_string(&mut buffer)?;
        //log::debug!("{}", buffer);
        let data = datastructures::FormData::from(buffer);

        let redis_conn = redis::Client::open("redis://127.0.0.1/")?;

        let ret = verify_login(&cfg, &data, redis_conn.clone()).await;

        if let Err(ref e) = ret {
            eprintln!("{:?}", e);
            log::error!("{:?}", e)
        }

        if ret.unwrap_or(false) {
            let cookie = Cookie::generate(data.get_user());
            let mut conn = redis_conn.get_async_connection().await?;

            conn.set_ex::<_, _, String>(
                format!("cgit_auth_{}", cookie.get_key()),
                cookie.get_body(),
                cfg.cookie_ttl as usize,
            )
                .await?;

            let cookie_value = cookie.to_string();

            let is_secure = matches
                .value_of("https")
                .map_or(false, |x| matches!(x, "yes" | "on" | "1"));
            let domain = matches.value_of("http-host").unwrap_or("*");
            let location = matches.value_of("http-referer").unwrap_or("/");
            let cookie_suffix = if is_secure { "; secure" } else { "" };
            writeln!(&mut self.writer, "Status: 302 Found")?;
            writeln!(&mut self.writer, "Cache-Control: no-cache, no-store")?;
            writeln!(&mut self.writer, "Location: {}", location)?;
            writeln!(&mut self.writer,
                "Set-Cookie: cgit_auth={}; Domain={}; Max-Age={}; HttpOnly{}",
                cookie_value, domain, cfg.cookie_ttl, cookie_suffix
            )?;
        } else {
            writeln!(&mut self.writer, "Status: 403 Forbidden")?;
            writeln!(&mut self.writer, "Cache-Control: no-cache, no-store")?;
        }

        writeln!(&mut self.writer)?;
        Ok(())
    }

}

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
        if let Ok(r) = conn
            .get::<_, String>(format!("cgit_auth_{}", cookie.get_key()))
            .await
        {
            if cookie.eq_body(r.as_str()) {
                return Ok(true);
            }
        }
        log::debug!("{:?}", cookie);
    }

    Ok(false)
}

async fn cmd_init(cfg: Config) -> Result<()> {
    let loc = std::path::Path::new(cfg.get_database_location());
    let exists = loc.exists();
    if !exists {
        std::fs::File::create(loc)?;
    }

    let mut conn = sqlx::SqliteConnection::connect(cfg.get_database_location()).await?;

    if exists {
        let rows = sqlx::query(r#"SELECT name FROM sqlite_master WHERE type='table' AND name=?"#)
            .bind("auth_meta")
            .fetch_all(&mut conn)
            .await?;

        if !rows.is_empty() {
            return Ok(())
        }
    }

    sqlx::query(database::current::CREATE_TABLES)
        .execute(&mut conn)
        .await?;
    println!("Initialize the database successfully");

    drop(conn);
    Ok(())
}

async fn verify_login(cfg: &Config, data: &FormData, redis_conn: redis::Client) -> Result<bool> {
    // TODO: use timestamp to mark file diff
    //       or copy in init process
    if cfg.test {
        std::fs::copy(
            cfg.get_database_location(),
            cfg.get_copied_database_location(),
        )?;
    }

    let mut rd = redis_conn.get_async_connection().await?;

    let mut conn = sqlx::sqlite::SqliteConnectOptions::from_str(
        cfg.get_copied_database_location().to_str().unwrap(),
    )?
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Off)
        .log_statements(log::LevelFilter::Trace)
        .connect()
        .await?;

    let (passwd_hash, uid) = sqlx::query_as::<_, (String, String)>(
        r#"SELECT "password", "uid" FROM "accounts" WHERE "user" = ?"#,
    )
    .bind(data.get_user())
    .fetch_one(&mut conn)
    .await?;

    let key = format!("cgit_repo_{}", data.get_user());
    if !rd.exists(&key).await? {
        if let Some((repos,)) =
            sqlx::query_as::<_, (String,)>(r#"SELECT "repos" FROM "repo" WHERE "uid" = ? "#)
                .bind(uid)
                .fetch_optional(&mut conn)
                .await?
        {
            let iter = repos.split_whitespace().collect::<Vec<&str>>();
            rd.sadd(&key, iter).await?;
        }
    }

    let parsed_hash = PasswordHash::new(passwd_hash.as_str()).unwrap();
    Ok(data.verify_password(&parsed_hash))
}

#[derive(Serialize)]
pub struct Meta<'a> {
    action: &'a str,
    redirect: &'a str,
    //custom_warning: &'a str,
}

// Processing the `body` called by cgit.
async fn cmd_body(matches: &ArgMatches<'_>, _cfg: Config) {
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
    let re = regex::Regex::new(r"^\w+$").unwrap();
    let user = matches.value_of("user").unwrap_or("");
    let passwd = matches.value_of("password").unwrap_or("").to_string();
    if user.is_empty() || passwd.is_empty() {
        return Err(anyhow::Error::msg("Invalid user or password length"));
    }

    if user.len() >= 20 {
        return Err(anyhow::Error::msg("Username length should less than 21"));
    }

    if !re.is_match(user) {
        return Err(anyhow::Error::msg(
            "Username must pass regex check\"^\\w+$\"",
        ));
    }

    let mut conn = sqlx::SqliteConnection::connect(cfg.get_database_location()).await?;

    let items = sqlx::query(r#"SELECT 1 FROM "accounts" WHERE "user" = ? "#)
        .bind(user)
        .fetch_all(&mut conn)
        .await?;

    if !items.is_empty() {
        return Err(anyhow::Error::msg("User already exists!"));
    }

    let uid = uuid::Uuid::new_v4().to_hyphenated().to_string();

    sqlx::query(r#"INSERT INTO "accounts" VALUES (?, ?, ?) "#)
        .bind(user)
        .bind(FormData::get_string_argon2_hash(&passwd)?)
        .bind(&uid)
        .execute(&mut conn)
        .await?;

    println!("Insert {} ({}) to database", user, uid);

    drop(conn);
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
        return Err(anyhow::Error::msg("Please input a valid username"));
    }

    let mut conn = sqlx::SqliteConnection::connect(cfg.get_database_location()).await?;

    let items = sqlx::query_as::<_, (i32,)>(r#"SELECT 1 FROM "accounts" WHERE "user" = ?"#)
        .bind(user)
        .fetch_all(&mut conn)
        .await?;

    if items.is_empty() {
        return Err(anyhow::Error::msg(format!("User {} not found", user)));
    }

    sqlx::query(r#"DELETE FROM "accounts" WHERE "user" = ?"#)
        .bind(user)
        .execute(&mut conn)
        .await?;

    println!("Delete {} from database", user);

    Ok(())
}

async fn cmd_reset_database(matches: &ArgMatches<'_>, cfg: Config) -> Result<()> {
    if !matches.is_present("confirm") {
        return Err(anyhow::Error::msg(
            "Please add --confirm argument to process reset",
        ));
    }

    let mut conn = SqliteConnection::connect(cfg.get_database_location()).await?;

    sqlx::query(database::current::DROP_TABLES)
        .execute(&mut conn)
        .await?;

    sqlx::query(database::current::CREATE_TABLES)
        .execute(&mut conn)
        .await?;

    println!("Reset database successfully");

    Ok(())
}

async fn cmd_upgrade_database(cfg: Config) -> Result<()> {
    let tmp_dir = TempDir::new("rolling")?;

    let v1_path = tmp_dir.path().join("v1.db");
    let v2_path = tmp_dir.path().join("v2.db");

    drop(std::fs::File::create(&v2_path).expect("Create v2 database failure"));

    std::fs::copy(cfg.get_database_location(), &v1_path)
        .expect("Copy v1 database to tempdir failure");

    let mut origin_conn = SqliteConnectOptions::from_str(v1_path.as_path().to_str().unwrap())?
        .read_only(true)
        .connect()
        .await?;

    let (v,) = sqlx::query_as::<_, (String,)>(
        r#"SELECT "value" FROM "auth_meta" WHERE "key" = 'version' "#,
    )
    .fetch_optional(&mut origin_conn)
    .await?
    .unwrap();

    #[allow(deprecated)]
    if v.eq(database::previous::VERSION) {
        let mut conn = SqliteConnection::connect(v2_path.as_path().to_str().unwrap()).await?;

        sqlx::query(database::current::CREATE_TABLES)
            .execute(&mut conn)
            .await?;

        let mut iter = sqlx::query_as::<_, (String, String)>(r#"SELECT * FROM "accounts""#)
            .fetch(&mut origin_conn);

        while let Some(Ok((user, passwd))) = iter.next().await {
            let uid = uuid::Uuid::new_v4().to_hyphenated().to_string();
            sqlx::query(r#"INSERT INTO "accounts" VALUES (?, ?, ?)"#)
                .bind(user.as_str())
                .bind(passwd)
                .bind(uid.as_str())
                .execute(&mut conn)
                .await?;
            log::debug!("Process user: {} ({})", user, uid);
        }
        drop(conn);

        std::fs::copy(&v2_path, cfg.get_database_location())
            .expect("Copy back to database location failure");
        println!("Upgrade database successful");
    } else {
        eprintln!(
            "Got database version {} but {} required",
            v,
            database::previous::VERSION
        )
    }
    drop(origin_conn);
    tmp_dir.close()?;

    Ok(())
}

async fn async_main(arg_matches: ArgMatches<'_>) -> Result<i32> {
    let cfg = if std::env::args().any(|x| x.eq("--test")) {
        Config::generate_test_config()
    } else {
        Config::new()
    };
    match arg_matches.subcommand() {
        ("authenticate-cookie", Some(matches)) => {
            if let Ok(should_pass) = cmd_authenticate_cookie(matches, cfg).await {
                if should_pass {
                    return Ok(1);
                }
            }
        }
        ("authenticate-post", Some(matches)) => {
            let stdin = std::io::stdin();
            let input = stdin.lock();

            let output = std::io::stdout();
            let mut module = IOModule {
                reader: input,
                writer: output
            };
            module.cmd_authenticate_post(matches, cfg).await?;
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
        ("reset", Some(matches)) => {
            cmd_reset_database(matches, cfg).await?;
        }
        ("upgrade", Some(_matches)) => {
            cmd_upgrade_database(cfg).await?;
        }
        _ => {}
    }
    Ok(0)
}

fn get_arg_matches(arguments: Option<Vec<&str>>) -> ArgMatches {

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

    let app = App::new("Simple Authentication Filter for cgit")
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
                .arg(Arg::with_name("user").required(true)),
        )
        .subcommand(
            SubCommand::with_name("reset")
                .about("Reset database")
                .arg(Arg::with_name("confirm").long("confirm")),
        )
        .subcommand(
            SubCommand::with_name("upgrade")
                .about("Upgrade database from v1(v0.1.x - v0.2.x) to v2(^v0.3.x)"),
        );

    let matches = if let Some(args) = arguments {
        app.get_matches_from(args)
    } else {
        app.get_matches()
    };

    matches
}

fn process_arguments() -> Result<()> {

    let ret = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async_main(get_arg_matches(None)))?;
    if ret == 1 {
        std::process::exit(1);
    }

    Ok(())
}

fn main() -> Result<()> {
    let logfile = FileAppender::builder()
        .encoder(Box::new(PatternEncoder::new(
            "{d(%Y-%m-%d %H:%M:%S)}- {h({l})} - {m}{n}",
        )))
        .build(env::var("RUST_LOG_FILE").unwrap_or("/tmp/auth.log".to_string()))?;

    let config = log4rs::Config::builder()
        .appender(Appender::builder().build("logfile", Box::new(logfile)))
        //.logger(log4rs::config::Logger::builder().build("sqlx::query", log::LevelFilter::Warn))
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
    log::debug!(
        "{}",
        env::args()
            .enumerate()
            .map(|(nth, arg)| format!("[{}]={}", nth, arg))
            .collect::<Vec<String>>()
            .join(" ")
    );

    process_arguments()?;

    Ok(())
}

#[cfg(test)]
mod test {
    use crate::{cmd_init, cmd_add_user};
    use std::path::PathBuf;
    use argon2::{
        password_hash::{PasswordHash, PasswordVerifier, PasswordHasher, SaltString},
        Argon2,
    };
    use crate::{IOModule, get_arg_matches};
    use crate::datastructures::{Config, rand_str};
    use redis::AsyncCommands;
    use std::time::Duration;
    use std::thread::sleep;
    use std::path::Path;
    const DEFAULT_ADD_USER_ARGS: &[&str] = &["adduser", "hunter2", "hunter2", "--test"];

    fn check_if_test_sqlite_only() -> bool {
        std::env::var("TEST_SQLITE").is_ok()
    }

    #[test]
    fn test_0_argon2() {
        use rand_core::OsRng;
        let passwd = b"hunter2";
        let salt = SaltString::generate(&mut OsRng);

        let argon2 = Argon2::default();

        argon2.hash_password_simple(passwd, salt.as_ref()).unwrap();
    }

    #[test]
    fn test_0_argon2_verify() {
        let passwd = b"hunter2";
        let parsed_hash = PasswordHash::new("$argon2id$v=19$m=4096,t=3,p=1$szYDnoQSVPmXq+RD2LneBw$fRETH//iCQuIX+SgjYPdZ9iIbM8gEy9fBjTJ/KFFJNM").unwrap();
        let argon2 = Argon2::default();
        assert!(argon2.verify_password(passwd, &parsed_hash).is_ok())
    }

    async fn async_test_redis() -> anyhow::Result<()> {
        let redis_conn = redis::Client::open("redis://127.0.0.1/")?;
        let mut conn = redis_conn.get_async_connection().await?;

        let s = rand_str(crate::datastructures::COOKIE_LENGTH);
        conn.set_ex::<_, _, String>("auth_test", &s, 60).await?;

        assert!(conn.exists::<_, bool>("auth_test").await?);

        assert_eq!(conn.get::<_, String>("auth_test").await?, s);

        conn.del("auth_test").await?;

        assert_eq!(conn.exists::<_, bool>("auth_test").await?, false);
        Ok(())
    }

    #[test]
    fn test_0_redis() {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async_test_redis())
            .unwrap();
    }

    fn write_test_result_to_redis() {

    }

    fn test_auth_post() -> String {

        let correct_input = br#"redirect=/&username=hunter2&password=hunter2"#;
        let matches = get_arg_matches(Some(vec![
            "a",
            "authenticate-post",
            "",
            "POST",
            "p=login",
            "https://git.example.com/?p=login",
            "/",
            "git.example.com",
            "",
            "",
            "login",
            "/?p=login",
            "/?p=login",
        ]));
        let mut output = Vec::new();
        let mut module = IOModule {
            reader: &correct_input[..],
            writer: &mut output,
        };

        let cfg = Config::generate_test_config();

        match matches.subcommand() {
            ("authenticate-post", Some(matches)) => {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(module.cmd_authenticate_post(matches, cfg))
                    .unwrap()
            }
            _ => {}
        }

        String::from_utf8(output).unwrap()

    }


    #[test]
    fn test_auth_failure() {
        if check_if_test_sqlite_only() {
            return
        }
        let out = test_auth_post();
        assert!(out.starts_with("Status: 403"))
    }

    #[test]
    fn test_0_init_database() {
        if !check_if_test_sqlite_only() {
            return
        }
        let tmp_dir = Path::new("test");
        use crate::datastructures::Config;

        if tmp_dir.exists() {
            std::fs::remove_dir_all(tmp_dir).unwrap();
        }
        std::fs::create_dir(tmp_dir).unwrap();
        let s = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("init --test")
            .spawn()
            .unwrap()
            .wait()
            .unwrap()
            .success();
    }


    fn lock(path: &std::path::PathBuf, sleep_length: usize) {
        for _ in 0..sleep_length {
            sleep(Duration::from_secs(1));
            if path.exists() {
                break
            }
        }

        if !path.exists() {
            panic!("Can't get lock from {}", path.to_str().unwrap())
        }
    }

    #[test]
    fn test_1_insert_user() {
        if !check_if_test_sqlite_only() {
            return
        }
        lock(&PathBuf::from("test/tmp.db"), 3);
        std::thread::sleep(std::time::Duration::from_secs(1));
        let s = std::process::Command::new(std::env::current_exe().unwrap())
            .args(DEFAULT_ADD_USER_ARGS)
            .spawn()
            .unwrap()
            .wait()
            .unwrap()
            .success();
        assert!(s);
    }

    #[test]
    fn test_auth_pass() {
        if check_if_test_sqlite_only() {
            return
        }
        let s = test_auth_post();

        println!("{}", s);
        assert!(s.starts_with("Status: 302"))

    }

}
