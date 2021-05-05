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


use sha2::Digest;
use anyhow::Result;

#[derive(Debug, Clone, Default)]
pub struct Config {

}

impl Config {
    pub fn new() -> Self {
        Self {}
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
        Self { ..Default::default()}
    }

    pub fn set_password(&mut self, password: String) {
        self.password = password;
        self.hash = Default::default();
    }

    pub fn set_user(&mut self, user: String) {
        self.user = user
    }

    pub fn get_user(&self) -> &String {
        &self.user
    }

    pub fn get_password_sha256(&self) -> Result<String> {
        let mut hasher = sha2::Sha256::new();
        hasher.update(self.password.as_bytes());
        Ok(format!("{:x}", hasher.finalize()))
    }

    #[allow(dead_code)]
    pub fn get_password_sha256_cache(&mut self) -> Result<String> {
        if self.hash.len() == 0 {
            self.hash = self.get_password_sha256()?;
        }
        Ok(self.hash.clone())
    }
}