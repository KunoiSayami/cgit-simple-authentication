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
#[deprecated(since = "0.3.0", note = "Please use v2 instead")]
#[allow(dead_code)]
pub mod v1 {
    pub const CREATE_TABLES: &str = r#"
    CREATE TABLE "accounts" (
        "user"	TEXT NOT NULL,
        "password"	TEXT NOT NULL,
        PRIMARY KEY("user")
    );


    CREATE TABLE "auth_meta" (
        "key"	TEXT NOT NULL,
        "value"	TEXT NOT NULL,
        PRIMARY KEY("key")
    );

    INSERT INTO "auth_meta" VALUES ('version', '1');
    "#;

    pub const DROP_TABLES: &str = r#"

    DROP TABLE "accounts";

    DROP TABLE "auth_meta";

    "#;

    pub const VERSION: &str = "1";
}

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

#[allow(deprecated)]
pub use v1 as previous;
pub use v2 as current;
pub use v2::VERSION;
