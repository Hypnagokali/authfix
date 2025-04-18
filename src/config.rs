#[derive(Clone)]
pub struct Routes {
    login: String,
    logout: String,
    mfa: String,
}

impl Routes {
    pub fn new(prefix: &str, login: &str, mfa: &str, logout: &str) -> Self {
        Self {
            login: create_uri(prefix, login),
            logout: create_uri(prefix, logout),
            mfa: create_uri(prefix, mfa),
        }
    }

    pub fn get_login(&self) -> &str {
        &self.login
    }
    pub fn get_logout(&self) -> &str {
        &self.logout
    }
    pub fn get_mfa(&self) -> &str {
        &self.mfa
    }
}

impl Default for Routes {
    fn default() -> Self {
        Self {
            login: "/login".to_owned(),
            logout: "/logout".to_owned(),
            mfa: "/login/mfa".to_owned(),
        }
    }
}

fn create_uri(prefix: &str, endpoint: &str) -> String {
    if prefix.trim() == "" || prefix.trim() == "/" {
        normalize_uri_part(endpoint)
    } else {
        format!(
            "{}{}",
            normalize_uri_part(prefix),
            normalize_uri_part(endpoint)
        )
    }
}

fn normalize_uri_part(part: &str) -> String {
    let mut normalized = part.to_owned().to_lowercase();

    if normalized.ends_with("/") && normalized.len() > 1 {
        normalized = normalized[0..(part.len() - 1)].to_owned();
    }

    if !normalized.starts_with("/") {
        normalized = format!("/{normalized}");
    }

    normalized
}

#[cfg(test)]
mod test {
    use super::Routes;
    use crate::config::normalize_uri_part;

    #[test]
    fn should_ignore_empty_prefix() {
        let routes = Routes::new("", "/login", "/mfa", "/logout");

        assert_eq!(routes.get_login(), "/login");
    }

    #[test]
    fn normalize_uri_part_test() {
        assert_eq!("/login/mfa", normalize_uri_part("/login/mfa/"));
        assert_eq!("/login/mfa", normalize_uri_part("login/mfa/"));
        assert_eq!("/login/mfa", normalize_uri_part("login/mfa"));
        assert_eq!("/", normalize_uri_part("/"));
        assert_eq!("/", normalize_uri_part(""));
    }
}
