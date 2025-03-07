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
#[deprecated(since = "0.4.0", note = "Please use v3 instead")]
#[allow(dead_code)]
pub mod v2 {
    pub const CREATE_TABLES: &str = r#"
    CREATE TABLE "accounts" (
        "user"	TEXT NOT NULL,
        "password"	TEXT NOT NULL,
        "uid" TEXT NOT NULL,
        PRIMARY KEY("user")
    );

    CREATE TABLE "auth_meta" (
        "key"	TEXT NOT NULL,
        "value"	TEXT NOT NULL,
        PRIMARY KEY("key")
    );

    CREATE TABLE "repo" (
        "uid"	TEXT NOT NULL,
        "repos"	TEXT NOT NULL,
        "expire"	INTEGER,
        PRIMARY KEY("uid")
    );

    INSERT INTO "auth_meta" VALUES ('version', '2');
    "#;

    pub const DROP_TABLES: &str = r#"

    DROP TABLE "accounts";

    DROP TABLE "repo";

    DROP TABLE "auth_meta";
    "#;

    pub const VERSION: &str = "2";
}

#[allow(dead_code)]
pub mod v3 {
    pub const CREATE_TABLES: &str = r#"
    CREATE TABLE "accounts" (
        "user"	TEXT NOT NULL,
        "password"	TEXT NOT NULL,
        "uid" TEXT NOT NULL,
        PRIMARY KEY("user")
    );

    CREATE TABLE "auth_meta" (
        "key"	TEXT NOT NULL,
        "value"	TEXT NOT NULL,
        PRIMARY KEY("key")
    );

    CREATE TABLE "repos" (
        "repo"	TEXT NOT NULL,
        "users" TEXT NOT NULL,
        PRIMARY KEY("repo")
    );

    INSERT INTO "auth_meta" VALUES ('version', '3');
    "#;

    pub const DROP_TABLES: &str = r#"

    DROP TABLE "accounts";

    DROP TABLE "repos";

    DROP TABLE "auth_meta";
    "#;

    pub const VERSION: &str = "3";
}

#[allow(deprecated)]
pub use v2 as previous;
pub use v3 as current;
