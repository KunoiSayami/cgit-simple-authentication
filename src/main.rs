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

use std::fs::OpenOptions;
use anyhow::Result;
use std::io::{Write, stdin, Read};
use std::{process, env};
use log::LevelFilter;
use syslog::{Formatter3164, Facility, BasicLogger};
use clap::{Arg, App, SubCommand, ArgMatches};
use rand::Rng;
use serde::{Serialize};
use handlebars::Handlebars;
use std::borrow::Cow;
use url::form_urlencoded;
use sqlx::Connection;
use crate::datastructures::{Config, FormData};
use redis::Commands;

const COOKIE_LENGTH: usize = 45;

fn rand_str(len: usize) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                        abcdefghijklmnopqrstuvwxyz\
                        0123456789";
    let mut rng = rand::thread_rng();

    let password: String = (0..len)
        .map(|_| {
            let idx = rng.gen_range(0, CHARSET.len());
            CHARSET[idx] as char
        })
        .collect();

    password
}


#[derive(Serialize)]
struct Meta<'a> {
    action: &'a str,
    redirect: &'a str,
}

// Verify username and password via gogs.
async fn verify_login(cfg: &Config, data: &FormData) -> Result<bool> {
    let mut conn = sqlx::SqliteConnection::connect("/tmp/database.db").await?;
    let password_sha = data.get_password_sha256()?;
    let ret = sqlx::query(r#"SELECT 1 FROM "accounts" WHERE "user" = ? AND "password" = ? "#)
        .bind(data.get_user())
        .bind(password_sha)
        .fetch_all(&mut conn)
        .await?;
    Ok(ret.len() > 0)
}


// Processing the `authenticate-basic` called by cgit.
fn cmd_authenticate_basic(
    matches: &ArgMatches,
    cfg: Option<Config>,
) -> Result<()> {
    unimplemented!()
}

// Processing the `authenticate-cookie` called by cgit.
async fn cmd_authenticate_cookie(
    matches: &ArgMatches<'_>,
    cfg: Option<Config>,
) -> Result<bool> {
    let cookies =  matches.value_of("http-cookie").unwrap_or("");

    if cookies.is_empty() {
        return Ok(false)
    }

    let mut conn = redis::Client::open("redis://127.0.0.1/")?;

    for cookie in cookies.split(';').map(|x| x.trim()) {
        let (key, value) = cookie.split_once('=').unwrap();
        if key.eq("cgit_auth") {
            if conn.get::<_, i32>(format!("cgit_auth_{}", value)).is_ok() {
                return Ok(true)
            }
            break
        }
    }

    Ok(false)
}


async fn cmd_init(cfg: Option<Config>) -> Result<()> {


    // TODO: read database location from configure file
    let mut conn = sqlx::SqliteConnection::connect("sqlite::memory:").await?;

    let rows = sqlx::query(r#"SELECT name FROM sqlite_master WHERE type='table' AND name=?"#)
        .bind("auth_meta")
        .fetch_all(&mut conn)
        .await?;

    if rows.is_empty() {
        sqlx::query(database::current::CREATE_TABLES)
            .execute(&mut conn)
            .await?;
    }

    Ok(())
}

// Processing the `authenticate-post` called by cgit.
async fn cmd_authenticate_post(
    matches: &ArgMatches<'_>,
    cfg: Option<Config>,
) -> Result<()> {
    // Load configurations.
    let cfg = cfg.unwrap_or_default();
    // Read stdin from upstream.
    let mut buffer = String::new();
    stdin().read_to_string(&mut buffer)?;
    let mut data = datastructures::FormData::new();
    // Parsing user posted form.
    let fields = form_urlencoded::parse(buffer.as_bytes());
    for f in fields {
        match f.0 {
            Cow::Borrowed("username") => {
                data.set_user(f.1.to_string())
            }
            Cow::Borrowed("password") => {
                data.set_password(f.1.to_string())
            }
            _ => {}
        }
    }

    // Authenticated via gogs.
    if verify_login(&cfg, &data).await.is_ok() {
        //let hash = data.hash();
        //let cgitauth = format!("{}:{}", hash, data.nonce);
        //let cgitauth_b64 = base64::encode_block(cgitauth.as_bytes());
        //let path = Path::new(&cfg.cache_dir).join(&hash);
        //data.to_file(path, true);
        let cookie = rand_str(COOKIE_LENGTH);

        //let redis = redis_async::client::connect(&SocketAddr::from_str("127.0.0.1:5432").unwrap()).await?;
        //redis.
        let mut conn = redis::Client::open("redis://127.0.0.1/")?;
        conn.set_ex::<_, &str, i32>(format!("cgit_auth_{}", cookie), "1", 600)?;

        let is_secure = matches
            .value_of("https")
            .map_or(false, |x| matches!(x, "yes" | "on" | "1"));
        let domain = matches.value_of("http-host").unwrap_or("*");
        let location = matches
            .value_of("current-url")
            .unwrap_or("/")
            .split('?')
            .next()
            .unwrap();
        let cookie_suffix = if is_secure { "; secure" } else { "" };
        println!("Status: 302 Redirect");
        println!("Cache-Control: no-cache, no-store");
        println!("Location: {}", location);
        println!(
            "Set-Cookie: cgit_auth={}; Domain={}; Max-Age={}; HttpOnly{}",
            // TODO: use cookie ttl instead
            //cookie, domain, cfg.cookie_ttl, cookie_suffix
            cookie, domain, 600, cookie_suffix
        );
    } else {
        println!("Status: 403 Forbidden");
        println!("Cache-Control: no-cache, no-store");
    }
    println!();


    Ok(())
}


// Processing the `body` called by cgit.
async fn cmd_body(matches: &ArgMatches<'_>, _cfg: Option<Config>) {
    let source = include_str!("authentication_page.html");
    let handlebars = Handlebars::new();
    let meta = Meta {
        action: matches.value_of("login-url").unwrap_or(""),
        redirect: matches.value_of("current-url").unwrap_or(""),
    };
    handlebars
        .render_template_to_write(source, &meta, std::io::stdout())
        .unwrap();
}

// Processing the `body` called by cron.
fn cmd_expire(_matches: &ArgMatches, cfg: Option<Config>) {
    unimplemented!();
}


async fn async_main(arg_matches: ArgMatches<'_>, cfg: Config) -> Result<i32>{
    match arg_matches.subcommand() {
        ("authenticate-cookie", Some(matches)) => {
            if cmd_authenticate_cookie(matches, Some(cfg)).await.is_ok() {
                return Ok(1)
            }
        }
        ("authenticate-post", Some(matches)) => {
            cmd_authenticate_post(matches, Some(cfg)).await.unwrap();
        }
        ("body", Some(matches)) => {
            cmd_body(matches, Some(cfg)).await;
        }
        ("expire", Some(matches)) => {
            cmd_expire(matches, Some(cfg));
        }
        ("init", Some(matches)) => {
            cmd_init(Some(cfg)).await?;
        }
        _ => {}
    }
    Ok(0)
}


fn main() -> Result<()>{

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("/tmp/output")?;
    let args = std::env::args().collect::<Vec<String>>().join(" ");
    //args.push("\n".into());
    file.write_all(args.as_bytes())?;
    file.write_all("\n".as_bytes())?;
    //println!(r#"<meta name="test">"#);


    let formatter = Formatter3164 {
        facility: Facility::LOG_USER,
        hostname: None,
        process: "cgit-gogs-auth-filter".into(),
        pid: process::id() as i32,
    };

    let logger = syslog::unix(formatter).expect("could not connect to syslog");
    if let Ok(()) = log::set_boxed_logger(Box::new(BasicLogger::new(logger))) {
        log::set_max_level(LevelFilter::Debug);
    }

    // Prints each argument on a separate line
    for (nth, argument) in env::args().enumerate() {
        log::debug!("[{}]={}", nth, argument);
    }

    // Sub-arguments for each command, see cgi defines.
    let sub_args = &[
        Arg::with_name("http-cookie").required(true),
        Arg::with_name("request-method").required(true),
        Arg::with_name("query-string").required(true),
        Arg::with_name("http-referer").required(true),
        Arg::with_name("path-info").required(true),
        Arg::with_name("http-host").required(true),
        Arg::with_name("https").required(true),
        Arg::with_name("repo").required(true),
        Arg::with_name("page").required(true),
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
        //.subcommand(SubCommand::with_name("expire").about("Check and clean all expired cookies"))
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