/*
 ** Copyright (C) 2021-2022 KunoiSayami
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

#[cfg(test)]
mod core {
    use crate::{
        authentication::{
            IOModule, cmd_add_user, cmd_authenticate_cookie, cmd_init, cmd_repo_user_control,
        },
        datastructures::{Config, TestSuite, rand_str},
        get_arg_matches,
    };
    use argon2::{
        Argon2,
        password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    };
    use redis::AsyncCommands;
    #[cfg(feature = "pam")]
    use std::borrow::BorrowMut;
    use std::io::{Read, Write};
    use std::path::Path;
    use std::path::PathBuf;
    use std::thread::sleep;
    use std::time::Duration;

    #[test]
    fn test_argon2() {
        use argon2::password_hash::rand_core::OsRng;
        let passwd = b"hunter2";
        let salt = SaltString::generate(&mut OsRng);

        let argon2 = Argon2::default();

        argon2.hash_password(passwd, &salt).unwrap();
    }

    #[test]
    fn test_argon2_verify() {
        let passwd = b"hunter2";
        let parsed_hash = PasswordHash::new("$argon2id$v=19$m=4096,t=3,p=1$szYDnoQSVPmXq+RD2LneBw$fRETH//iCQuIX+SgjYPdZ9iIbM8gEy9fBjTJ/KFFJNM").unwrap();
        let argon2 = Argon2::default();
        assert!(argon2.verify_password(passwd, &parsed_hash).is_ok())
    }

    async fn async_test_redis() -> anyhow::Result<()> {
        let redis_conn = redis::Client::open("redis://127.0.0.1/")?;
        let mut conn = redis_conn.get_multiplexed_async_connection().await?;

        let s = rand_str(crate::datastructures::COOKIE_LENGTH);
        conn.set_ex::<_, _, String>("auth_test", &s, 60).await?;

        assert!(conn.exists::<_, bool>("auth_test").await?);

        assert_eq!(conn.get::<_, String>("auth_test").await?, s);

        let _: () = conn.del("auth_test").await?;

        assert_eq!(conn.exists::<_, bool>("auth_test").await?, false);
        Ok(())
    }

    #[test]
    fn test_redis() {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async_test_redis())
            .unwrap();
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
        let mut module = IOModule::new(&correct_input[..], &mut output);

        let cfg = Config::generate_test_config();

        match matches.subcommand() {
            Some(("authenticate-post", matches)) => tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(module.cmd_authenticate_post(matches, cfg))
                .unwrap(),
            _ => {}
        }

        String::from_utf8(output).unwrap()
    }

    #[test]
    fn test_01_auth_failure() {
        let out = test_auth_post();
        assert!(out.starts_with("Status: 403"));
        assert!(out.ends_with("\n\n"));
    }

    #[test]
    fn test_00_init_database() {
        let tmp_dir = Path::new("test");

        if tmp_dir.exists() {
            std::fs::remove_dir_all(tmp_dir).unwrap();
        }
        std::fs::create_dir(tmp_dir).unwrap();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(cmd_init(Config::generate_test_config()))
            .unwrap();
        std::fs::File::create("test/DATABASE_INITED").unwrap();
    }

    fn lock(path: &PathBuf, sleep_length: usize) {
        for _ in 0..(sleep_length * 100) {
            sleep(Duration::from_millis(10));
            if path.exists() {
                break;
            }
        }

        if !path.exists() {
            panic!("Can't get lock from {}", path.to_str().unwrap())
        }
    }

    #[test]
    fn test_02_insert_user() {
        lock(&PathBuf::from("test/DATABASE_INITED"), 3);
        let matches = get_arg_matches(Some(vec!["a", "user", "add", "hunter2", "hunter2"]));
        match matches.subcommand() {
            Some(("user", matches)) => match matches.subcommand() {
                Some(("add", matches)) => {
                    tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .unwrap()
                        .block_on(cmd_add_user(matches, Config::generate_test_config()))
                        .unwrap();
                    std::fs::File::create("test/USER_WRITTEN").unwrap();
                }
                _ => unreachable!(),
            },
            _ => unreachable!(),
        }
        assert!(Path::new("test/COMMIT").exists())
    }

    #[test]
    fn test_03_insert_repo() {
        lock(&PathBuf::from("test/USER_WRITTEN"), 5);
        let args = vec![
            vec!["a", "repo", "add", "test", "hunter2"],
            vec!["a", "repo", "add", "repo", "hunter"],
        ];
        for x in args {
            let matches = get_arg_matches(Some(x));
            match matches.subcommand() {
                Some(("repo", matches)) => match matches.subcommand() {
                    Some(("add", matches)) => {
                        tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()
                            .unwrap()
                            .block_on(cmd_repo_user_control(
                                matches,
                                Config::generate_test_config(),
                                false,
                            ))
                            .unwrap();
                        std::fs::File::create("test/REPO_USER_ADDED").unwrap();
                    }
                    _ => unreachable!(),
                },
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn test_91_auth_pass() {
        lock(&PathBuf::from("test/REPO_USER_ADDED"), 10);
        // If process is too fast, this function may got Database locked error
        sleep(Duration::from_millis(
            option_env!("DISK_WAIT_TIME")
                .unwrap_or("10")
                .parse()
                .unwrap_or(10),
        ));

        let s = test_auth_post();

        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open("test/RESPONSE")
            .unwrap();
        file.write_all(s.as_bytes()).unwrap();

        assert!(s.starts_with("Status: 302"));
        assert!(s.ends_with("\n\n"));
        assert!(!Path::new("test/COPIED").exists());
    }

    #[test]
    fn test_92_authenticate_cookie() {
        test_authenticate_cookie("test", Some("test/COOKIE_TEST_1"));
    }

    #[test]
    #[should_panic]
    fn test_93_authenticate_cookie_failure() {
        test_authenticate_cookie("repo", Some("test/COOKIE_TEST_2"));
    }

    fn test_authenticate_cookie<P: AsRef<Path>>(repo: &str, path: Option<P>) {
        lock(&PathBuf::from("test/RESPONSE"), 15);
        let mut buffer = String::new();

        let mut file = std::fs::File::open("test/RESPONSE").unwrap();
        file.read_to_string(&mut buffer).unwrap();

        let buffer = buffer;

        let mut cookie = "";

        for line in buffer.lines().map(|x| x.trim()) {
            if !line.starts_with("Set-Cookie") {
                continue;
            }
            let (_, value) = line.split_once(":").unwrap();
            let (value, _) = value.split_once(";").unwrap();
            cookie = value.trim();
            break;
        }

        let matches = get_arg_matches(Some(vec![
            "a",
            "authenticate-cookie",
            cookie,
            "GET",
            "",
            "https://git.example.com/",
            "/",
            "git.example.com",
            "on",
            repo,
            "",
            "/",
            "/?p=login",
        ]));
        let result = match matches.subcommand() {
            Some(("authenticate-cookie", matches)) => tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(cmd_authenticate_cookie(
                    matches,
                    Config::generate_test_config(),
                ))
                .unwrap(),
            _ => unreachable!(),
        };
        if let Some(path) = path {
            std::fs::File::create(path).unwrap();
        }
        assert!(result);
    }

    fn write_to_specify_file(path: &PathBuf, data: &[u8]) -> Result<(), std::io::Error> {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)?;
        file.write_all(data)?;
        file.sync_all()?;
        Ok(())
    }

    #[test]
    fn test_protected_repo_parser() {
        let tmpdir = tempfile::TempDir::new().unwrap();

        let another_file_path = format!(
            "include={}/REPO_SETTING # TEST\ncgit-simple-auth-protect=part",
            tmpdir.path().to_str().unwrap()
        );
        write_to_specify_file(&tmpdir.path().join("CFG"), another_file_path.as_bytes()).unwrap();
        write_to_specify_file(
            &tmpdir.path().join("REPO_SETTING"),
            b"repo.url=test\nrepo.protect=true",
        )
        .unwrap();

        let cfg = Config::load_from_path(tmpdir.path().join("CFG"));

        assert!(cfg.check_repo_protect("test"), "struct: {:#?}", cfg);
        assert!(!cfg.get_white_list_mode_status());
        assert!(!cfg.query_is_all_protected());

        write_to_specify_file(
            &tmpdir.path().join("REPO_SETTING"),
            b"repo.protect=true\nrepo.url=test",
        )
        .unwrap();

        let cfg = Config::load_from_path(tmpdir.path().join("CFG"));

        assert!(!cfg.check_repo_protect("test"));
        assert!(!cfg.get_white_list_mode_status());
        assert!(!cfg.query_is_all_protected());

        tmpdir.close().unwrap();
    }

    async fn clear_redis_setting() -> anyhow::Result<()> {
        let client = redis::Client::open("redis://127.0.0.1")?;
        let mut conn = client.get_multiplexed_async_connection().await?;

        for key in &["cgit_repo_test", "cgit_repo_repo"] {
            conn.del::<_, i32>(*key).await?;
        }
        Ok(())
    }

    #[test]
    fn test_99_clear() {
        lock(&PathBuf::from("test/COOKIE_TEST_1"), 9);
        lock(&PathBuf::from("test/COOKIE_TEST_2"), 6);
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(clear_redis_setting())
            .unwrap();
    }

    #[cfg(feature = "pam")]
    #[ignore]
    #[test]
    fn test_pam() {
        let service = option_env!("pam_service").unwrap_or("system-auth");
        let user = option_env!("pam_user").unwrap_or("user");
        let password = option_env!("pam_password").unwrap_or("password");

        let mut auth = pam::Client::with_password(service).unwrap();
        auth.conversation_mut()
            .borrow_mut()
            .set_credentials(user, password);
        assert!(auth.authenticate().is_ok() && auth.open_session().is_ok())
    }
}
