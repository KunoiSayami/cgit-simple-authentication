# Cgit Simple Authentication

Simple authentication filter for [cgit](https://wiki.archlinux.org/title/Cgit) powered by [SQLite](https://wiki.archlinux.org/title/SQLite) and [Redis](https://wiki.archlinux.org/title/Redis).

## Features

- Cookie-based session authentication with configurable TTL
- Password hashing with [Argon2](https://en.wikipedia.org/wiki/Argon2)
- Per-repository access control lists (ACL)
- Flexible protection modes: protect all repos, selected repos, or none
- Optional [PAM](https://wiki.archlinux.org/title/PAM) authentication support
- Session storage via Redis for fast cookie validation
- Built-in login page served by the filter
- Database migration support (v2 to v3)
- Pre-built binaries for Linux (amd64/aarch64) and macOS (arm64)

## Requirements

- [Rust](https://www.rust-lang.org/) (for building from source)
- [Redis](https://wiki.archlinux.org/title/Redis) (running on `127.0.0.1`)
- [cgit](https://wiki.archlinux.org/title/Cgit) with `auth-filter` support

## Building

```shell
cargo build --release
```

The binary will be at `target/release/cgit-simple-authentication`.

## Getting Started

### 1. Initialize the database

```shell
cgit-simple-authentication database init
```

This creates the SQLite database at the configured location (default: `/etc/cgit/auth.db`).

### 2. Add a user

```shell
cgit-simple-authentication user add admin hunter2
```

### 3. Configure cgit

Add the filter to your `cgitrc`:

```conf
auth-filter=/opt/cgit-simple-authentication/cgit-simple-authentication
```

## Configuration

All options are set in the `cgitrc` file:

| Option | Default | Description |
|---|---|---|
| `cgit-simple-auth-cookie-ttl` | `1200` | Cookie time to live in seconds |
| `cgit-simple-auth-database` | `/etc/cgit/auth.db` | SQLite database file path |
| `cgit-simple-auth-bypass-root` | `false` | Skip authentication on the repository list (root) page |
| `cgit-simple-auth-protect` | `full` | Protection mode: `full`, `part`, or `none` |
| `cgit-simple-auth-use-pam` | `false` | PAM service name, or `false` to disable |

### Protection Modes

- **`full`** (default) -- All repositories require authentication. Individual repos can opt out with `repo.protect=false`.
- **`part`** -- No repositories are protected by default. Individual repos can opt in with `repo.protect=true`.
- **`none`** -- Authentication is disabled entirely.

### Per-Repository Configuration

When using `part` mode, enable protection for specific repositories:

```conf
repo.url=my-private-repo
repo.protect=true
```

When using `full` mode, disable protection for specific repositories:

```conf
repo.url=my-public-repo
repo.protect=false
```

### Repository ACL

When a repository is protected, you can control which users have access:

```shell
# Grant a user access to a repository
cgit-simple-authentication repo add my-repo alice

# Revoke a user's access
cgit-simple-authentication repo del my-repo alice

# Remove all users from a repository's ACL
cgit-simple-authentication repo del my-repo --clear-all

# List all repository ACLs
cgit-simple-authentication repo list

# Show ACL for a specific repository
cgit-simple-authentication repo list my-repo
```

### PAM Authentication

To authenticate against system users via PAM instead of the built-in SQLite database, enable the `pam` feature at compile time and set the PAM service name:

```shell
cargo build --release --features pam
```

```conf
cgit-simple-auth-use-pam=system-auth
```

### Logging

Logs are written to `/var/cache/cgit/auth.log` by default. Override with the `LOG_FILE` environment variable.

## User Management

```shell
# Add a user
cgit-simple-authentication user add <username> <password>

# Delete a user
cgit-simple-authentication user del <username>

# List all users
cgit-simple-authentication user list
```

## Database Management

```shell
# Initialize the database
cgit-simple-authentication database init

# Upgrade from v2 (0.3.x) to v3 (0.4.x+)
cgit-simple-authentication database upgrade

# Reset the database (requires --confirm)
cgit-simple-authentication database reset --confirm
```

## Acknowledgments

Inspired by: https://github.com/varphone/cgit-gogs-auth-filter

## License

[![](https://www.gnu.org/graphics/agplv3-155x51.png)](https://www.gnu.org/licenses/agpl-3.0.txt)

Copyright (C) 2021-2026 KunoiSayami

This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public License as published by the Free Software Foundation, either version 3 of the License, or any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.
