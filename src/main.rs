/*
 ** Copyright (C) 2021-2022-2022 KunoiSayami
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
#[cfg(test)]
mod test;

use crate::datastructures::{AuthorizerType, Config, Cookie, FormData, TestSuite, WrapConfigure};
use anyhow::Result;
use clap::{Arg, ArgMatches, Command};
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
use std::str::FromStr;
use tempdir::TempDir;
use tokio_stream::StreamExt as _;

struct IOModule<R, W> {
    reader: R,
    writer: W,
}

impl<R: BufRead, W: Write> IOModule<R, W> {
    // Processing the `authenticate-post` called by cgit.
    async fn cmd_authenticate_post(&mut self, matches: &ArgMatches, cfg: Config) -> Result<()> {
        // Read stdin from upstream.
        let mut buffer = String::new();
        self.reader.read_to_string(&mut buffer)?;

        //log::debug!("{}", buffer);
        let data = datastructures::FormData::from(buffer);

        let cfg = WrapConfigure::from(cfg);
        log::trace!("Method is {}", cfg.get_authorizer().method());
        let ret = verify_login(&cfg, &data).await;

        if let Err(ref e) = ret {
            eprintln!("{:?}", e);
            #[cfg(test)]
            eprintln!(
                "If database locked error occurs frequently, \
            please use environment DISK_WAIT_TIME to specify longer time."
            );
            log::error!("{:?}", e)
        }

        if ret.unwrap_or(false) {
            let redis_conn = redis::Client::open("redis://127.0.0.1/")?;
            let cookie = Cookie::generate(data.get_user());
            let mut conn = redis_conn.get_async_connection().await?;

            conn.set_ex::<_, _, String>(
                format!("cgit_auth_{}", cookie.get_key()),
                cookie.get_body(),
                cfg.get_config().cookie_ttl as usize,
            )
            .await?;

            let cookie_value = cookie.to_string();

            let is_secure = matches
                .get_one::<String>("https")
                .map(|s| s.as_str())
                .map_or(false, |x| matches!(x, "yes" | "on" | "1"));
            let domain = matches
                .get_one::<String>("http-host")
                .map(|s| s.as_str())
                .unwrap_or("*");
            let location = matches
                .get_one::<String>("http-referer")
                .map(|s| s.as_str())
                .unwrap_or("/");
            let cookie_suffix = if is_secure { "; secure" } else { "" };
            writeln!(&mut self.writer, "Status: 302 Found")?;
            writeln!(&mut self.writer, "Cache-Control: no-cache, no-store")?;
            writeln!(&mut self.writer, "Location: {}", location)?;
            writeln!(
                &mut self.writer,
                "Set-Cookie: cgit_auth={}; Domain={}; Max-Age={}; HttpOnly{}",
                cookie_value,
                domain,
                cfg.get_config().cookie_ttl * 10,
                cookie_suffix
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
async fn cmd_authenticate_cookie(matches: &ArgMatches, cfg: Config) -> Result<bool> {
    let cookies = matches
        .get_one::<String>("http-cookie")
        .map(|s| s.as_str())
        .unwrap_or("");
    let repo = matches
        .get_one::<String>("repo")
        .map(|s| s.as_str())
        .unwrap_or("");
    /*let current_url = matches.value_of("current-url").unwrap_or("");*/

    let mut bypass = false;

    if cfg.bypass_root /*&& current_url.eq("/")*/ && repo.is_empty() {
        bypass = true;
    }

    if bypass || (!repo.is_empty() && !cfg.check_repo_protect(repo)) {
        return Ok(true);
    }

    if cookies.is_empty() {
        return Ok(false);
    }

    let redis_conn = redis::Client::open("redis://127.0.0.1/")?;
    let mut conn = redis_conn.get_async_connection().await?;

    let redis_key = format!("cgit_repo_{}", repo);
    if !repo.is_empty() && !conn.exists(&redis_key).await? {
        let sql_conn = SqliteConnectOptions::from_str(cfg.get_database_location())?
            .read_only(true)
            .immutable(true)
            .disable_statement_logging()
            .connect()
            .await;
        if let Err(ref e) = sql_conn {
            log::error!(
                "Got error while open sqlite connection: {:?}\nDatabase location: {}",
                e,
                cfg.get_database_location()
            );
        }
        let mut sql_conn = sql_conn?;
        if let Some((users,)) =
            sqlx::query_as::<_, (String,)>(r#"SELECT "users" FROM "repos" WHERE "repo" = ? "#)
                .bind(repo)
                .fetch_optional(&mut sql_conn)
                .await?
        {
            let users = users.split_whitespace().collect::<Vec<&str>>();
            conn.sadd(&redis_key, users).await?;
        }
    }

    if let Ok(Some(cookie)) = Cookie::load_from_request(cookies) {
        log::debug!("Cookie is {:?}", &cookie);
        if let Ok(r) = conn
            .get::<_, String>(format!("cgit_auth_{}", cookie.get_key()))
            .await
        {
            conn.expire::<_, bool>(
                format!("cgit_auth_{}", cookie.get_key()),
                cfg.cookie_ttl as usize,
            )
            .await?;
            if cookie.eq_body(r.as_str()) {
                if repo.is_empty() {
                    return Ok(true);
                }
                if conn
                    .sismember::<_, _, i32>(&redis_key, cookie.get_user())
                    .await?
                    == 1
                {
                    return Ok(true);
                }
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

    let mut conn = SqliteConnection::connect(cfg.get_database_location()).await?;

    if exists {
        let rows = sqlx::query(r#"SELECT name FROM sqlite_master WHERE type='table' AND name=?"#)
            .bind("auth_meta")
            .fetch_all(&mut conn)
            .await?;

        if !rows.is_empty() {
            return Ok(());
        }
    }

    sqlx::query(database::current::CREATE_TABLES)
        .execute(&mut conn)
        .await?;
    println!("Initialize the database successfully");

    drop(conn);

    cfg.write_database_commit_timestamp().await?;
    Ok(())
}

async fn verify_login(cfg: &WrapConfigure, data: &FormData) -> Result<bool> {
    if let AuthorizerType::Password = cfg.get_authorizer().method() {
        cfg.hook().await?;
    }
    data.authorize(cfg.get_authorizer()).await
}

#[derive(Serialize)]
pub struct Meta<'a> {
    action: &'a str,
    redirect: &'a str,
    version: &'a str,
}

// Processing the `body` called by cgit.
async fn cmd_body(matches: &ArgMatches, _cfg: Config) {
    let source = include_str!("authentication_page.html");
    let handlebars = Handlebars::new();
    let meta = Meta {
        action: matches
            .get_one::<String>("login-url")
            .map(|s| s.as_str())
            .unwrap_or(""),
        redirect: matches
            .get_one::<String>("current-url")
            .map(|s| s.as_str())
            .unwrap_or(""),
        version: env!("CARGO_PKG_VERSION"),
    };
    handlebars
        .render_template_to_write(source, &meta, std::io::stdout())
        .unwrap();
}

async fn cmd_add_user(matches: &ArgMatches, cfg: Config) -> Result<()> {
    let re = regex::Regex::new(r"^\w+$").unwrap();
    let user = matches
        .get_one::<String>("user")
        .map(|s| s.as_str())
        .unwrap_or("");
    let passwd = matches
        .get_one::<String>("password")
        .map(|s| s.to_string())
        .unwrap_or_else(|| "".to_string());
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

    let mut conn = SqliteConnection::connect(cfg.get_database_location()).await?;

    let items = sqlx::query(r#"SELECT 1 FROM "accounts" WHERE "user" = ? "#)
        .bind(user)
        .fetch_all(&mut conn)
        .await?;

    if !items.is_empty() {
        return Err(anyhow::Error::msg("User already exists!"));
    }

    let uid = uuid::Uuid::new_v4().to_string();

    sqlx::query(r#"INSERT INTO "accounts" VALUES (?, ?, ?) "#)
        .bind(user)
        .bind(FormData::gen_string_argon2_hash(&passwd)?)
        .bind(&uid)
        .execute(&mut conn)
        .await?;

    println!("Insert {} ({}) to database", user, uid);

    drop(conn);

    cfg.write_database_commit_timestamp().await?;
    Ok(())
}

async fn cmd_list_user(cfg: Config) -> Result<()> {
    let mut conn = SqliteConnection::connect(cfg.get_database_location()).await?;

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

async fn cmd_delete_user(matches: &ArgMatches, cfg: Config) -> Result<()> {
    let user = matches
        .get_one::<String>("user")
        .map(|s| s.as_str())
        .unwrap_or("");
    if user.is_empty() {
        return Err(anyhow::Error::msg("Please input a valid username"));
    }

    let mut conn = SqliteConnection::connect(cfg.get_database_location()).await?;

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

    cfg.write_database_commit_timestamp().await?;
    Ok(())
}

async fn cmd_reset_database(matches: &ArgMatches, cfg: Config) -> Result<()> {
    if !matches.contains_id("confirm") {
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

    cfg.write_database_commit_timestamp().await?;
    Ok(())
}

async fn cmd_upgrade_database(cfg: Config) -> Result<()> {
    let tmp_dir = TempDir::new("rolling")?;

    let v2_path = tmp_dir.path().join("v2.db");
    let v3_path = tmp_dir.path().join("v3.db");

    drop(std::fs::File::create(&v3_path).expect("Create v3 database failure"));

    std::fs::copy(cfg.get_database_location(), &v2_path)
        .expect("Copy v2 database to tempdir failure");

    let mut origin_conn = SqliteConnectOptions::from_str(v2_path.as_path().to_str().unwrap())?
        .read_only(true)
        .immutable(true)
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
        let mut conn = SqliteConnection::connect(v3_path.as_path().to_str().unwrap()).await?;

        sqlx::query(database::current::CREATE_TABLES)
            .execute(&mut conn)
            .await?;

        let mut iter = sqlx::query_as::<_, (String, String, String)>(r#"SELECT * FROM "accounts""#)
            .fetch(&mut origin_conn);

        while let Some(Ok((user, passwd, uid))) = iter.next().await {
            sqlx::query(r#"INSERT INTO "accounts" VALUES (?, ?, ?)"#)
                .bind(user.as_str())
                .bind(passwd)
                .bind(uid.as_str())
                .execute(&mut conn)
                .await?;
            log::debug!("Process user: {} ({})", user, uid);
        }
        drop(conn);

        std::fs::copy(&v3_path, cfg.get_database_location())
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

    cfg.write_database_commit_timestamp().await?;
    Ok(())
}

async fn cmd_repo_user_control(matches: &ArgMatches, cfg: Config, is_delete: bool) -> Result<()> {
    let repo = matches
        .get_one::<String>("repo")
        .map(|s| s.as_str())
        .unwrap_or("");
    let user = matches
        .get_one::<String>("user")
        .map(|s| s.as_str())
        .unwrap_or("");

    let clear_all = is_delete && matches.contains_id("clear-all");

    if repo.is_empty()
        || (is_delete && !clear_all && user.is_empty())
        || (!is_delete && user.is_empty())
    {
        return Err(anyhow::Error::msg("Invalid repository or username"));
    }

    let redis_client = redis::Client::open("redis://127.0.0.1/")?;
    let mut redis_conn = redis_client.get_async_connection().await?;

    let mut conn = SqliteConnection::connect(cfg.get_database_location()).await?;

    if sqlx::query(r#"SELECT "users" FROM "repos" WHERE "repo" = ?"#)
        .bind(repo)
        .fetch_optional(&mut conn)
        .await?
        .is_none()
    {
        if is_delete {
            println!("Row is empty.");
            return Ok(());
        }
        sqlx::query(r#"INSERT INTO "repos" VALUES (?, ?)"#)
            .bind(repo)
            .bind("")
            .execute(&mut conn)
            .await?;
    }

    let (users,) =
        sqlx::query_as::<_, (String,)>(r#"SELECT "users" FROM "repos" WHERE "repo" = ?"#)
            .bind(repo)
            .fetch_optional(&mut conn)
            .await?
            .unwrap();
    let mut users = users.split_whitespace().collect::<Vec<&str>>();

    if let Some(index) = users.clone().into_iter().position(|x| x.eq(user)) {
        if is_delete {
            if clear_all {
                users.clear();
            } else {
                users.remove(index);
            }
        } else {
            return Err(anyhow::Error::msg("User already in repository ACL"));
        }
    }

    if !is_delete {
        users.push(user);
    }

    sqlx::query(r#"UPDATE "repos" SET "users" = ? WHERE "repo" = ?"#)
        .bind(users.join(" "))
        .bind(repo)
        .execute(&mut conn)
        .await?;

    let redis_key = format!("cgit_repo_{}", repo);
    if redis_conn.exists::<_, i32>(&redis_key).await? == 0 {
        redis_conn.sadd::<_, _, i32>(&redis_key, users).await?;
    } else if is_delete {
        if clear_all {
            redis_conn.del::<_, i32>(&redis_key).await?;
        } else {
            redis_conn.srem::<_, _, i32>(&redis_key, user).await?;
        }
    } else {
        redis_conn.sadd::<_, _, i32>(&redis_key, user).await?;
    }

    if !clear_all {
        println!(
            "{} user {} {} repository {} ACL successful",
            if is_delete { "Delete" } else { "Add" },
            user,
            if is_delete { "from" } else { "to" },
            repo,
        );
    } else {
        println!("Clear all users from repository {} ACL", repo);
    }

    Ok(())
}

async fn cmd_list_repos_acl(arg_matches: &ArgMatches, cfg: Config) -> Result<()> {
    let repo = arg_matches
        .get_one::<String>("repo")
        .map(|s| s.as_str())
        .unwrap_or("");

    let mut conn = SqliteConnectOptions::from_str(cfg.get_database_location())?
        .read_only(true)
        .immutable(true)
        .connect()
        .await?;

    if repo.is_empty() {
        let (length,) = sqlx::query_as::<_, (i32,)>(r#"SELECT COUNT(*) FROM "repos""#)
            .fetch_optional(&mut conn)
            .await?
            .unwrap_or((0,));

        println!(
            "There is total {} {} in database",
            length,
            if length == 1 {
                "repository"
            } else {
                "repositories"
            },
        );

        let mut iter =
            sqlx::query_as::<_, (String, String)>(r#"SELECT * FROM "repos""#).fetch(&mut conn);
        while let Some(Ok((repo, users))) = iter.next().await {
            println!(
                "{}: {}",
                repo,
                users
                    .split_whitespace()
                    .into_iter()
                    .collect::<Vec<&str>>()
                    .join(",")
            )
        }
    } else {
        let ret =
            sqlx::query_as::<_, (String, String)>(r#"SELECT * FROM "repos" WHERE "repo" = ?"#)
                .bind(repo)
                .fetch_optional(&mut conn)
                .await?;
        if let Some((repo, users)) = ret {
            println!(
                "{}: {}",
                repo,
                users
                    .split_whitespace()
                    .into_iter()
                    .collect::<Vec<&str>>()
                    .join(",")
            )
        } else {
            println!("Repository {} not register in database", repo)
        }
    }

    Ok(())
}

async fn async_main(arg_matches: ArgMatches) -> Result<i32> {
    let cfg = if env::args().any(|x| x.eq("--test")) {
        Config::generate_test_config()
    } else {
        Config::new()
    };
    match arg_matches.subcommand() {
        Some(("authenticate-cookie", matches)) => {
            if let Ok(should_pass) = cmd_authenticate_cookie(matches, cfg).await {
                if should_pass {
                    return Ok(1);
                }
            }
        }
        Some(("authenticate-post", matches)) => {
            let stdin = std::io::stdin();
            let input = stdin.lock();

            let output = std::io::stdout();
            let mut module = IOModule {
                reader: input,
                writer: output,
            };
            module.cmd_authenticate_post(matches, cfg).await?;
        }
        Some(("body", matches)) => {
            cmd_body(matches, cfg).await;
        }
        Some(("user", matches)) => match matches.subcommand() {
            Some(("add", matches)) => {
                cmd_add_user(matches, cfg).await?;
            }
            Some(("del", matches)) => {
                cmd_delete_user(matches, cfg).await?;
            }
            Some(("list", _matches)) => {
                cmd_list_user(cfg).await?;
            }
            _ => {}
        },
        Some(("database", matches)) => match matches.subcommand() {
            Some(("init", _matches)) => {
                cmd_init(cfg).await?;
            }
            Some(("upgrade", _matches)) => {
                cmd_upgrade_database(cfg).await?;
            }
            Some(("reset", matches)) => {
                cmd_reset_database(matches, cfg).await?;
            }
            _ => {}
        },
        Some(("repo", matches)) => match matches.subcommand() {
            Some(("add", matches)) => cmd_repo_user_control(matches, cfg, false).await?,
            Some(("del", matches)) => {
                cmd_repo_user_control(matches, cfg, true).await?;
            }
            Some(("list", matches)) => {
                cmd_list_repos_acl(matches, cfg).await?;
            }
            _ => {}
        },
        _ => {}
    }
    Ok(0)
}

fn get_arg_matches(arguments: Option<Vec<&str>>) -> ArgMatches {
    // Sub-arguments for each command, see cgi defines.
    let sub_args = &[
        Arg::new("http-cookie"), // 2
        Arg::new("request-method"),
        Arg::new("query-string"),
        Arg::new("http-referer"), // 5
        Arg::new("path-info"),
        Arg::new("http-host"),
        Arg::new("https"),
        Arg::new("repo"),
        Arg::new("page"), // 10
        Arg::new("current-url"),
        Arg::new("login-url"),
    ];

    let app = Command::new("Simple Authentication Filter for cgit")
        .version(env!("CARGO_PKG_VERSION"))
        .subcommand(
            Command::new("authenticate-cookie")
                .about("Processing authenticated cookie")
                .args(sub_args)
                .hide(true),
        )
        .subcommand(
            Command::new("authenticate-post")
                .about("Processing posted username and password")
                .args(sub_args)
                .hide(true),
        )
        .subcommand(
            Command::new("body")
                .about("Return the login form")
                .args(sub_args)
                .hide(true),
        )
        .subcommand(
            Command::new("database")
                .about("Database rated commands")
                .subcommand(
                    Command::new("init")
                        .about("Init sqlite database")
                        .display_order(0),
                )
                .subcommand(
                    Command::new("reset")
                        .about("Reset database")
                        .arg(Arg::new("confirm").long("confirm"))
                        .display_order(0),
                )
                .subcommand(
                    Command::new("upgrade")
                        .about("Upgrade database from v2(v0.3.x) to v3(^v0.4.x)")
                        .display_order(0),
                )
                .display_order(0),
        )
        .subcommand(
            Command::new("user")
                .about("Users rated commands")
                .subcommand(
                    Command::new("add")
                        .about("Add user to database")
                        .arg(Arg::new("user").required(true))
                        .arg(Arg::new("password").required(true))
                        .display_order(0),
                )
                .subcommand(
                    Command::new("del")
                        .about("Delete user from database")
                        .arg(Arg::new("user").required(true))
                        .display_order(0),
                )
                .subcommand(
                    Command::new("list")
                        .about("List all users")
                        .display_order(0),
                )
                .display_order(0),
        )
        .subcommand(
            Command::new("repo")
                .about("Repository ACL rated commands")
                .subcommand(
                    Command::new("add")
                        .about("Add user to repository")
                        .arg(Arg::new("repo").required(true))
                        .arg(Arg::new("user").required(true))
                        .display_order(0),
                )
                .subcommand(
                    Command::new("del")
                        .about("Del user from repository")
                        .arg(Arg::new("repo"))
                        .arg(Arg::new("user"))
                        .arg(Arg::new("clear-all").conflicts_with("user"))
                        .display_order(0),
                )
                .subcommand(
                    Command::new("list")
                        .about("Show all repositories or only show specify repository detail")
                        .arg(Arg::new("repo"))
                        .display_order(0),
                )
                .display_order(0),
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
    let logfile_path =
        env::var("LOG_FILE").unwrap_or_else(|_| "/var/cache/cgit/auth.log".to_string());
    let logfile = FileAppender::builder()
        .encoder(Box::new(PatternEncoder::new(
            "{d(%Y-%m-%d %H:%M:%S)}- {h({l})} - {m}{n}",
        )))
        .build(&logfile_path);
    let logfile = match logfile {
        Ok(f) => f,
        Err(e) => {
            return Err(anyhow::Error::msg(format!(
                "Got error while append to {}: {:?}",
                &logfile_path, e
            )))
        }
    };

    let config = log4rs::Config::builder()
        .appender(Appender::builder().build("logfile", Box::new(logfile)))
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

    if let Err(e) = process_arguments() {
        log::error!("{:?}", e);
    };

    Ok(())
}
