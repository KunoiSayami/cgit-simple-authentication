/*
 ** Copyright (C) 2021-2023 KunoiSayami
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

mod authentication;
mod database;
mod datastructures;
#[cfg(test)]
mod test;

use crate::datastructures::{Config, TestSuite};
use anyhow::Result;
use clap::{Arg, ArgMatches, Command};
use log4rs::append::file::FileAppender;
use log4rs::config::{Appender, Root};
use log4rs::encode::pattern::PatternEncoder;
use std::env;

async fn async_main(arg_matches: ArgMatches) -> Result<i32> {
    let cfg = if env::args().any(|x| x.eq("--test")) {
        Config::generate_test_config()
    } else {
        Config::new()
    };
    match arg_matches.subcommand() {
        Some(("authenticate-cookie", matches)) => {
            if let Ok(should_pass) = authentication::cmd_authenticate_cookie(matches, cfg).await {
                if should_pass {
                    return Ok(1);
                }
            }
        }
        Some(("authenticate-post", matches)) => {
            let stdin = std::io::stdin();
            let input = stdin.lock();

            let output = std::io::stdout();
            let mut module = authentication::IOModule::new(input, output);
            module.cmd_authenticate_post(matches, cfg).await?;
        }
        Some(("body", matches)) => {
            authentication::cmd_body(matches, cfg).await;
        }
        Some(("user", matches)) => match matches.subcommand() {
            Some(("add", matches)) => {
                authentication::cmd_add_user(matches, cfg).await?;
            }
            Some(("del", matches)) => {
                authentication::cmd_delete_user(matches, cfg).await?;
            }
            Some(("list", _matches)) => {
                authentication::cmd_list_user(cfg).await?;
            }
            _ => {}
        },
        Some(("database", matches)) => match matches.subcommand() {
            Some(("init", _matches)) => {
                authentication::cmd_init(cfg).await?;
            }
            Some(("upgrade", _matches)) => {
                authentication::cmd_upgrade_database(cfg).await?;
            }
            Some(("reset", matches)) => {
                authentication::cmd_reset_database(matches, cfg).await?;
            }
            _ => {}
        },
        Some(("repo", matches)) => match matches.subcommand() {
            Some(("add", matches)) => {
                authentication::cmd_repo_user_control(matches, cfg, false).await?
            }
            Some(("del", matches)) => {
                authentication::cmd_repo_user_control(matches, cfg, true).await?;
            }
            Some(("list", matches)) => {
                authentication::cmd_list_repos_acl(matches, cfg).await?;
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

    if let Some(args) = arguments {
        app.get_matches_from(args)
    } else {
        app.get_matches()
    }
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
            return Err(anyhow::anyhow!(
                "Got error while append to {logfile_path}: {e:?}",
            ));
        }
    };

    let config = log4rs::Config::builder()
        .appender(Appender::builder().build("logfile", Box::new(logfile)))
        .loggers([
            log4rs::config::Logger::builder().build("handlebars::render", log::LevelFilter::Warn),
            log4rs::config::Logger::builder().build("handlebars::context", log::LevelFilter::Warn),
        ])
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
            .map(|(nth, arg)| format!("[{nth}]={arg}"))
            .collect::<Vec<String>>()
            .join(" ")
    );

    if let Err(e) = process_arguments() {
        log::error!("{e:?}");
    };

    Ok(())
}
