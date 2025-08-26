use serde::{Deserialize, Serialize};
use sqlx::{FromRow, Row};

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ProxyContext {
    pub account: String,
    pub scope: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(i32)]
pub enum Permission {
    Basic = 0,
    Verified = 1,
    Calendar = 2,
    Wiki = 3,
    Bulletin = 4,
    Game = 5,
    Host = 6,
    User = 7,
    Statistics = 8,
    DevOps = 9,
}

impl From<i32> for Permission {
    fn from(value: i32) -> Self {
        match value {
            0 => Permission::Basic,
            1 => Permission::Verified,
            2 => Permission::Calendar,
            3 => Permission::Wiki,
            4 => Permission::Bulletin,
            5 => Permission::Game,
            6 => Permission::Host,
            7 => Permission::User,
            8 => Permission::Statistics,
            9 => Permission::DevOps,
            _ => Permission::Basic,
        }
    }
}

#[derive(Debug, Clone)]
pub struct User {
    pub id: i64,
    pub account: String,
    pub nickname: String,
    pub password: String,
    pub email: String,
    pub permissions: Vec<i32>,
    pub hidden: bool,
    pub banned: bool,
}

impl<'r> FromRow<'r, sqlx::postgres::PgRow> for User {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        // Handle permissions as JSONB
        let permissions_json: serde_json::Value = row.try_get("permissions")?;
        let permissions: Vec<i32> = permissions_json
            .as_array()
            .ok_or_else(|| sqlx::Error::ColumnDecode {
                index: "permissions".to_string(),
                source: Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "permissions is not an array",
                )),
            })?
            .iter()
            .filter_map(|v| v.as_i64().map(|n| n as i32))
            .collect();

        Ok(User {
            id: row.try_get("id")?,
            account: row.try_get("account")?,
            nickname: row.try_get("nickname")?,
            password: row.try_get("password")?,
            email: row.try_get("email")?,
            permissions,
            hidden: row.try_get("hidden")?,
            banned: row.try_get("banned")?,
        })
    }
}

impl User {
    pub fn has_permission(&self, permission: Permission) -> bool {
        self.permissions.contains(&(permission as i32))
    }

    pub fn can_authenticate(&self) -> bool {
        self.has_permission(Permission::Verified) && !self.banned
    }

    pub fn can_access_registry(&self) -> bool {
        self.has_permission(Permission::Game)
    }

    pub fn can_write_library(&self) -> bool {
        self.has_permission(Permission::Game) && self.has_permission(Permission::DevOps)
    }
}

#[derive(Debug, Clone)]
pub struct Game {
    pub id: i64,
    pub bucket: String,
    pub admins: Vec<i64>,
}

impl<'r> FromRow<'r, sqlx::postgres::PgRow> for Game {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        // Handle admins as JSONB
        let admins_json: serde_json::Value = row.try_get("admins")?;
        let admins: Vec<i64> = admins_json
            .as_array()
            .ok_or_else(|| sqlx::Error::ColumnDecode {
                index: "admins".to_string(),
                source: Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "admins is not an array",
                )),
            })?
            .iter()
            .filter_map(|v| v.as_i64())
            .collect();

        Ok(Game {
            id: row.try_get("id")?,
            bucket: row.try_get("bucket")?,
            admins,
        })
    }
}

impl Game {
    pub fn is_admin(&self, user_id: i64) -> bool {
        self.admins.contains(&user_id)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub iss: String,
    pub aud: String,
    pub exp: usize,
    pub nbf: usize,
    pub iat: usize,
    pub jti: String,
    pub access: Vec<AccessEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AccessEntry {
    pub r#type: String,
    pub name: String,
    pub actions: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct AuthRequest {
    pub service: Option<String>,
    pub scope: Option<String>,
    pub account: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub token: String,
    pub access_token: String,
    pub expires_in: u64,
    pub issued_at: String,
}
