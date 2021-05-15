# Cgit simple authentication

Simple authentication for [cgit](https://wiki.archlinux.org/title/Cgit) powered by [sqlite](https://wiki.archlinux.org/title/SQLite) and [redis](https://wiki.archlinux.org/title/Redis)

## Configure

Add this project as cgit [`auth-filter`](https://man.archlinux.org/man/cgitrc.5#FILTER_API)

```conf
auth-filter=/opt/cgit-simple-authentication/target/release/cgit-simple-authentication
```

Available options for this filter:

```conf
# Set cookie time to live
cgit-simple-auth-cookie-ttl=600
# Specify database location (Default is /etc/cgit/auth.db) 
cgit-simple-auth-database=/etc/cgit/auth.db
# Should authenticate in repositories root view
cgit-simple-auth-bypass-root=false
# Should enable authenticate in all repository
cgit-simple-auth-full-protect=true
```

Available options for repositories:

_Should set `cgit-simple-auth-full-protect=false`_ 

```conf
repo.url=test
# Enable protect for this repository
repo.protect=true
```

## Source

Most of the ideas come from: https://github.com/varphone/cgit-gogs-auth-filter

## License

[![](https://www.gnu.org/graphics/agplv3-155x51.png)](https://www.gnu.org/licenses/agpl-3.0.txt)

Copyright (C) 2021 KunoiSayami

This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public License as published by the Free Software Foundation, either version 3 of the License, or any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.
