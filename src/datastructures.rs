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

use anyhow::Result;
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use rand::Rng;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::fmt::Formatter;
use std::fs::read_to_string;
use std::path::{Path, PathBuf};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use url::form_urlencoded;

const DEFAULT_CONFIG_LOCATION: &str = "/etc/cgitrc";
const DEFAULT_COOKIE_TTL: u64 = 1200;
const DEFAULT_DATABASE_LOCATION: &str = "/etc/cgit/auth.db";
pub const CACHE_DIR: &str = "/var/cache/cgit";
pub type RandIntType = u32;
//pub const MINIMUM_SECRET_LENGTH: usize = 8;
pub const COOKIE_LENGTH: usize = 32;

pub fn get_current_timestamp() -> u64 {
    let start = std::time::SystemTime::now();
    let since_the_epoch = start
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Time went backwards");
    since_the_epoch.as_secs()
}

pub fn rand_int() -> RandIntType {
    let mut rng = rand::thread_rng();
    rng.gen()
}

pub fn rand_str(len: usize) -> String {
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

#[derive(Debug, Clone)]
pub struct Config {
    pub cookie_ttl: u64,
    database: String,
    //access_node: hashmap,
    pub bypass_root: bool,
    //secret: String,
    pub(crate) test: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            cookie_ttl: DEFAULT_COOKIE_TTL,
            database: DEFAULT_DATABASE_LOCATION.to_string(),
            bypass_root: false,
            //secret: Default::default(),
            test: false,
        }
    }
}

impl Config {
    pub fn new() -> Self {
        Self::load_from_path(DEFAULT_CONFIG_LOCATION)
    }

    pub fn load_from_path<P: AsRef<Path>>(path: P) -> Self {
        let file = read_to_string(path).unwrap_or_default();
        let mut cookie_ttl: u64 = DEFAULT_COOKIE_TTL;
        let mut database: &str = "/etc/cgit/auth.db";
        let mut bypass_root: bool = false;
        //let mut secret: &str = "";
        for line in file.lines() {
            let line = line.trim();
            if !line.contains('=') || !line.starts_with("cgit-simple-auth-") {
                continue;
            }

            let (key, value) = if line.contains('#') {
                line.split_once('#').unwrap().0.split_once('=').unwrap()
            } else {
                line.split_once('=').unwrap()
            };
            let key_name = key.split_once("auth-").unwrap().1.trim();
            match key_name {
                "cookie-ttl" => cookie_ttl = value.parse().unwrap_or(DEFAULT_COOKIE_TTL),
                "database" => database = value,
                "bypass-root" => bypass_root = value.to_lowercase().eq("true"),
                //"secret" => secret = value,
                _ => {}
            }
        }
        Self {
            cookie_ttl,
            database: database.to_string(),
            bypass_root,
            test: false,
            //secret: secret.to_string(),
        }
    }

    pub fn get_database_location(&self) -> &str {
        self.database.as_str()
    }

    pub fn get_copied_database_location(&self) -> PathBuf {
        if self.test {
            return PathBuf::from(self.database.as_str());
        }

        std::path::Path::new(CACHE_DIR).join(
            std::path::Path::new(self.get_database_location())
                .file_name()
                .unwrap(),
        )
    }

    pub(crate) fn generate_test_config() -> Self {
        Self {
            database: "test/tmp.db".to_string(),
            bypass_root: false,
            cookie_ttl: DEFAULT_COOKIE_TTL,
            test: true,
        }
    }

    async fn read_timestamp_from_file<P: AsRef<Path>>(path: P) -> Result<u64> {
        let mut file = tokio::fs::File::open(path).await?;
        let mut buffer = String::new();
        file.read_to_string(&mut buffer).await?;
        Ok(buffer.trim().parse()?)
    }

    pub async fn get_last_commit_timestamp(&self) -> Result<u64> {
        Self::read_timestamp_from_file(format!(
            "{}/COMMIT",
            if self.test { "test" } else { CACHE_DIR }
        ))
        .await
    }

    pub async fn get_last_copy_timestamp(&self) -> Result<u64> {
        Self::read_timestamp_from_file(format!(
            "{}/COPIED",
            if self.test { "test" } else { CACHE_DIR }
        ))
        .await
    }

    async fn write_current_timestamp_to_file<P: AsRef<Path>>(path: P) -> Result<()> {
        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(path)
            .await?;
        file.write_all(format!("{}", get_current_timestamp()).as_bytes())
            .await?;
        Ok(())
    }

    pub async fn write_database_commit_timestamp(&self) -> Result<()> {
        Self::write_current_timestamp_to_file(format!(
            "{}/COMMIT",
            if self.test { "test" } else { CACHE_DIR }
        ))
        .await
    }

    pub async fn write_last_copy_timestamp(&self) -> Result<()> {
        Self::write_current_timestamp_to_file(format!(
            "{}/COPIED",
            if self.test { "test" } else { CACHE_DIR }
        ))
        .await
    }
}

#[derive(Debug, Clone, Default)]
pub struct FormData {
    user: String,
    password: String,
    hash: String,
}

impl FormData {
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }

    pub fn get_string_argon2_hash(s: &str) -> Result<String> {
        let passwd = s.as_bytes();
        let salt = SaltString::generate(&mut OsRng);

        let argon2_alg = Argon2::default();

        Ok(argon2_alg
            .hash_password_simple(passwd, salt.as_ref())
            .unwrap()
            .to_string())
    }

    pub fn set_password(&mut self, password: String) {
        self.password = password;
        self.hash = Default::default();
    }

    pub fn verify_password(&self, password_hash: &PasswordHash) -> bool {
        let argon2_alg = Argon2::default();
        argon2_alg
            .verify_password(self.password.as_bytes(), password_hash)
            .is_ok()
    }

    pub fn set_user(&mut self, user: String) {
        self.user = user
    }

    pub fn get_user(&self) -> &String {
        &self.user
    }

    pub fn get_password_argon2(&self) -> Result<String> {
        Self::get_string_argon2_hash(&self.password)
    }

    #[allow(dead_code)]
    pub fn get_password_argon2_cache(&mut self) -> Result<String> {
        if self.hash.is_empty() {
            self.hash = self.get_password_argon2()?;
        }
        Ok(self.hash.clone())
    }

    #[allow(dead_code)]
    pub fn get_argon2_without_calc(&self) -> &String {
        &self.hash
    }
}

impl From<&[u8]> for FormData {
    fn from(input: &[u8]) -> Self {
        let fields = form_urlencoded::parse(input);
        let mut data = Self::new();
        for f in fields {
            match f.0 {
                Cow::Borrowed("username") => {
                    data.set_user(f.1.to_string());
                }
                Cow::Borrowed("password") => {
                    data.set_password(f.1.to_string());
                }
                _ => {}
            }
        }
        data
    }
}

impl From<&String> for FormData {
    fn from(s: &String) -> Self {
        Self::from(s.as_bytes())
    }
}

impl From<String> for FormData {
    fn from(s: String) -> Self {
        Self::from(&s)
    }
}

#[derive(Serialize, Deserialize)]
struct IvFile {
    iv: String,
    timestamp: u64,
}

#[derive(Debug)]
pub struct Cookie {
    timestamp: u64,
    randint: RandIntType,
    user: String,
    reversed: String,
}

impl Cookie {
    fn new(randint: RandIntType, user: &str) -> Self {
        Self {
            timestamp: get_current_timestamp(),
            randint,
            user: user.to_string(),
            reversed: rand_str(COOKIE_LENGTH),
        }
    }

    pub fn load_from_request(cookies: &str) -> Result<Option<Self>> {
        let mut cookie_self = None;
        for cookie in cookies.split(';').map(|x| x.trim()) {
            let (key, value) = cookie.split_once('=').unwrap();
            if key.eq("cgit_auth") {
                let value = base64::decode(value).unwrap_or_default();
                let value = std::str::from_utf8(&value).unwrap_or("");

                if !value.contains(';') {
                    break;
                }

                let (key, value) = value.split_once(';').unwrap();

                let (user, reversed) = value.split_once(";").unwrap_or(("", ""));

                let (timestamp, randint) = key.split_once("_").unwrap_or(("0", ""));

                cookie_self = Some(Self {
                    timestamp: timestamp.parse()?,
                    randint: randint.parse()?,
                    user: user.trim().to_string(),
                    reversed: reversed.trim().to_string(),
                });
                break;
            }
        }
        Ok(cookie_self)
    }

    pub fn eq_body(&self, s: &str) -> bool {
        self.get_body().eq(s)
    }

    pub fn get_key(&self) -> String {
        format!("{}_{}", self.timestamp, self.randint)
    }

    pub fn get_user(&self) -> &str {
        self.user.as_str()
    }

    pub fn get_body(&self) -> String {
        format!("{}; {}", self.user, self.reversed)
    }

    pub fn generate(user: &str) -> Self {
        Self::new(rand_int(), user)
    }
}

impl std::fmt::Display for Cookie {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let s = format!(
            "{}_{}; {}; {}",
            self.timestamp, self.randint, self.user, self.reversed
        );
        write!(f, "{}", base64::encode(s))
    }
}

/*
pub struct CookieOrigin {
    timestamp: u64,
    randint: RandIntType,
    user: String,
    rand_str: String,
}

impl CookieOrigin {
    pub fn new(randint: RandIntType, user: &String, rand_str: &String) -> Self {
        Self {
            timestamp: get_current_timestamp(),
            randint,
            user: user.clone(),
            rand_str: rand_str.clone(),
        }
    }

    pub async fn to_cookie(&self, cfg: &Config) -> Result<Cookie> {
        let mut file = File::open(Path::new(CACHE_DIR).join(DEFAULT_IV_FILE_NAME)).await?;
        let mut context = String::new();
        file.read_to_string(&mut context).await?;
        let iv_file: IvFile = serde_json::from_str(&context)?;
        let key = cfg.secret.to_hex();
        let iv = iv_file.iv.to_hex();

        let mut cipher = Blowfish::new(key);

        cipher.write_all().awa

        let mut buffer = [0u8, 128];

        let plain_text = format!("{}, {}", self.user, self.rand_str);

        let pos = plain_text.len();

        buffer[..pos].copy_from_slice(plain_text.as_bytes());

        let b = Block::from_mut_slice(&mut buffer);


        Ok(())
    }
}
*/
