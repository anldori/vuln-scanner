use ipnet::IpNet;
use std::net::IpAddr;
use std::str::FromStr;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TargetError {
    #[error("target is empty")]
    Empty,
    #[error("target is too long")]
    TooLong,
    #[error("target contains invalid characters")]
    InvalidChars,
    #[error("target must not start with '-' or '.'")]
    BadStart,
    #[error("target is not a valid IP, CIDR or hostname")]
    Invalid,
    #[error("target is outside the allowed scope")]
    OutOfScope,
}

/// A validated scan target. Can only be built through [`Target::parse`], so any
/// `Target` is safe to pass as a single argv entry to an external tool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Ip(IpAddr),
    Cidr(IpNet),
    Host(String),
}

impl Target {
    pub fn parse(input: &str) -> Result<Target, TargetError> {
        let s = input.trim();
        if s.is_empty() {
            return Err(TargetError::Empty);
        }
        if s.len() > 253 {
            return Err(TargetError::TooLong);
        }
        if s.starts_with('-') || s.starts_with('.') {
            return Err(TargetError::BadStart);
        }
        if let Ok(ip) = IpAddr::from_str(s) {
            return Ok(Target::Ip(ip));
        }
        if s.contains('/') {
            return IpNet::from_str(s).map(Target::Cidr).map_err(|_| TargetError::Invalid);
        }
        if !s.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-') {
            return Err(TargetError::InvalidChars);
        }
        if s.split('.').any(|l| l.is_empty() || l.len() > 63 || l.starts_with('-') || l.ends_with('-')) {
            return Err(TargetError::Invalid);
        }
        Ok(Target::Host(s.to_ascii_lowercase()))
    }

    /// Value to pass to external tools.
    pub fn as_arg(&self) -> String {
        match self {
            Target::Ip(i) => i.to_string(),
            Target::Cidr(n) => n.to_string(),
            Target::Host(h) => h.clone(),
        }
    }
}

/// Allowlist of networks and hostnames that may be scanned.
#[derive(Debug, Clone, Default)]
pub struct Scope {
    /// `SCOPE=any`: every syntactically valid target is allowed.
    any: bool,
    nets: Vec<IpNet>,
    hosts: Vec<String>,
}

impl Scope {
    /// Build from a comma-separated list, e.g. `127.0.0.0/8,192.168.1.0/24,scanme.nmap.org`.
    pub fn parse_list(list: &str) -> Result<Scope, TargetError> {
        let mut scope = Scope::default();
        for item in list.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            if item == "*" || item.eq_ignore_ascii_case("any") {
                scope.any = true;
                continue;
            }
            match Target::parse(item)? {
                Target::Ip(ip) => scope.nets.push(IpNet::from(ip)),
                Target::Cidr(n) => scope.nets.push(n),
                Target::Host(h) => scope.hosts.push(h),
            }
        }
        Ok(scope)
    }

    /// Human-readable list of what is allowed, e.g. `127.0.0.0/8, 192.168.1.5/32, lab.local`.
    pub fn describe(&self) -> String {
        if self.any {
            return "ANY target (no scope restriction)".into();
        }
        let mut v: Vec<String> = self.nets.iter().map(|n| n.to_string()).collect();
        v.extend(self.hosts.iter().cloned());
        v.join(", ")
    }

    pub fn check(&self, t: &Target) -> Result<(), TargetError> {
        if self.any {
            return Ok(());
        }
        let ok = match t {
            Target::Ip(ip) => self.nets.iter().any(|n| n.contains(ip)),
            Target::Cidr(c) => self.nets.iter().any(|n| n.contains(&c.network()) && n.contains(&c.broadcast())),
            Target::Host(h) => self.hosts.iter().any(|a| a == h),
        };
        if ok {
            Ok(())
        } else {
            Err(TargetError::OutOfScope)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_targets() {
        assert!(matches!(Target::parse("127.0.0.1"), Ok(Target::Ip(_))));
        assert!(matches!(Target::parse("10.0.0.0/24"), Ok(Target::Cidr(_))));
        assert!(matches!(Target::parse("Scanme.Nmap.org"), Ok(Target::Host(h)) if h == "scanme.nmap.org"));
        assert!(matches!(Target::parse("::1"), Ok(Target::Ip(_))));
    }

    #[test]
    fn rejects_injection_attempts() {
        assert_eq!(Target::parse("-oN /tmp/x"), Err(TargetError::BadStart));
        assert_eq!(Target::parse("--script=evil"), Err(TargetError::BadStart));
        assert!(Target::parse("a.com; rm -rf /").is_err());
        assert_eq!(Target::parse("a.com -p-"), Err(TargetError::InvalidChars));
        assert_eq!(Target::parse(""), Err(TargetError::Empty));
        assert_eq!(Target::parse("a..com"), Err(TargetError::Invalid));
    }

    #[test]
    fn scope_any_allows_everything_valid_but_not_garbage() {
        let s = Scope::parse_list("any").unwrap();
        assert!(s.check(&Target::parse("8.8.8.8").unwrap()).is_ok());
        assert!(s.check(&Target::parse("10.0.0.0/8").unwrap()).is_ok());
        assert!(s.check(&Target::parse("example.com").unwrap()).is_ok());
        assert!(Target::parse("-oN x").is_err()); // validation still applies
    }

    #[test]
    fn scope_enforced() {
        let s = Scope::parse_list("127.0.0.0/8, 192.168.1.0/24, lab.local").unwrap();
        assert!(s.check(&Target::parse("127.0.0.1").unwrap()).is_ok());
        assert!(s.check(&Target::parse("192.168.1.0/25").unwrap()).is_ok());
        assert!(s.check(&Target::parse("lab.local").unwrap()).is_ok());
        assert_eq!(s.check(&Target::parse("8.8.8.8").unwrap()), Err(TargetError::OutOfScope));
        assert_eq!(s.check(&Target::parse("192.168.0.0/16").unwrap()), Err(TargetError::OutOfScope));
        assert_eq!(s.check(&Target::parse("evil.com").unwrap()), Err(TargetError::OutOfScope));
    }
}
