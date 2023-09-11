//! Module for internal and external capability definitions
//!
//! # Internal capability representation
//!
//! Internally, the capabilities are represented by instances of the struct§
//! [`Capability`]. This struct never affects the external representation and
//! it is safe to modify it in any way.
//!
//! # External capability representation
//!
//! When we want to serialize or deserialize [`Capability`], we convert the
//! struct to the [`SerializableCapability`] enum. Variants of this enum are
//! different historical versions included for backwards compatibility. The
//! latest version is called [`SerializableCapability::Latest`] and any
//! instance of the enum can be upgraded to this variant by calling the
//! [`SerializableCapability::upgrade()`] method.
//!
//! The external representation is completely transparent to the rest of the
//! modules. From the outside, the internal [`Capability`] struct can be
//! directly serialized and deserialized. The conversion happens in the custom
//! implementation of the [`Serialize`] and [`Deserialize`] traits.

use std::{
    ffi::OsStr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde_derive::{Deserialize, Serialize};

fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[derive(Deserialize, Serialize, Debug, Clone)]
enum SerializableCapability {
    #[serde(rename = "1")]
    Latest(V1Capability),
}

/// First serialization format for the Capability
///
/// Note: the awful one letter naming makes the URLs shorter
#[derive(Deserialize, Serialize, Debug, Clone)]
struct V1Capability {
    /// path name
    p: String,
    /// size limit in bytes (u64::MAX = non-enforcing)
    s: u64,
    /// timeout (unix timestamp)
    t: u64,
    /// owner of this capability is allowed to download files
    r: bool,
    /// owner of this capability is allowed to upload files
    w: bool,
    /// owner of this capability is allowed to list directories
    x: bool,
    /// owner of this capability is allowed to modify this capability
    c: bool,
}

impl SerializableCapability {
    /// Upgrade the enum variant to [`SerializableCapability::Latest`].
    fn upgrade(&mut self) {
        // currently nothing is necessary
    }
}

/// Internal representation of a capability.
#[derive(Debug, Clone)]
pub struct Capability {
    /// path name
    path: String,
    /// size limit in bytes (u64::MAX = non-enforcing)
    size_limit: u64,
    /// timeout (unix timestamp)
    timeout: u64,
    /// owner of this capability is allowed to download files
    allow_reading: bool,
    /// owner of this capability is allowed to upload files
    allow_writing: bool,
    /// owner of this capability is allowed to list directories
    allow_listing: bool,
    /// owner of this capability is allowed to modify this capability
    allow_changing: bool,
}

impl From<SerializableCapability> for Capability {
    fn from(mut value: SerializableCapability) -> Self {
        // upgrade the serialized capability to the Latest version
        value.upgrade();
        assert!(matches!(value, SerializableCapability::Latest(_)));

        // construct the internal capability representation
        let SerializableCapability::Latest(inner) = value;
        Capability {
            path: inner.p,
            size_limit: inner.s,
            timeout: inner.t,
            allow_reading: inner.r,
            allow_writing: inner.w,
            allow_listing: inner.x,
            allow_changing: inner.c,
        }
    }
}

impl From<&Capability> for SerializableCapability {
    fn from(value: &Capability) -> Self {
        SerializableCapability::Latest(V1Capability {
            p: value.path.clone(),
            s: value.size_limit,
            t: value.timeout,
            r: value.allow_reading,
            w: value.allow_writing,
            x: value.allow_listing,
            c: value.allow_changing,
        })
    }
}

impl Capability {
    pub fn size_limit(&self) -> u64 {
        self.size_limit
    }

    pub fn is_enforcing_size_limit(&self) -> bool {
        self.size_limit != u64::MAX
    }

    pub fn is_enforcing_time_limit(&self) -> bool {
        self.timeout != u64::MAX
    }

    /// Construct a capability with full privileges
    pub fn root() -> Self {
        Capability {
            path: ".".to_owned(),
            size_limit: u64::MAX,
            timeout: u64::MAX,
            allow_writing: true,
            allow_reading: true,
            allow_listing: true,
            allow_changing: true,
        }
    }

    pub fn is_expired(&self) -> bool {
        self.timeout < current_unix_timestamp()
    }

    pub fn expiration_time(&self) -> SystemTime {
        let dur = Duration::from_secs(self.timeout);
        match UNIX_EPOCH.checked_add(dur) {
            Some(exp_time) => exp_time,
            None => {
                // the link is valid for u64::MAX seconds and an overflow happens
                // the following expression also results in a huge timestamp far away in the future,
                // but it does not overflow
                UNIX_EPOCH + Duration::MAX.div_f64(4.0)
            }
        }
    }

    /// Works properly only when not expired
    pub fn remaining_time_secs(&self) -> u64 {
        assert!(!self.is_expired());
        self.timeout - current_unix_timestamp()
    }

    pub fn path(&self) -> &async_std::path::Path {
        async_std::path::Path::new(&self.path)
    }

    pub fn child(&self, name: &OsStr) -> Self {
        //FIXME better name
        let mut new = self.clone();
        let newpath = new.path().join(name);
        new.path = newpath.to_string_lossy().into(); // FIXME this is wrong, the `p` field should probably be OsString or just a byte array
        new
    }

    pub fn can_list(&self) -> bool {
        self.allow_listing
    }

    pub fn can_read(&self) -> bool {
        self.allow_reading
    }

    pub fn can_write(&self) -> bool {
        self.allow_writing
    }

    pub fn can_be_modified(&self) -> bool {
        self.allow_changing
    }

    pub fn block_listing(self) -> Self {
        Capability {
            allow_listing: false,
            ..self
        }
    }

    pub fn block_reading(self) -> Self {
        Capability {
            allow_reading: false,
            ..self
        }
    }

    pub fn block_writing(self) -> Self {
        Capability {
            allow_writing: false,
            ..self
        }
    }

    pub fn block_capability_modifications(self) -> Self {
        Capability {
            allow_changing: false,
            ..self
        }
    }

    pub fn set_size_limit(self, new: u64) -> Self {
        Capability {
            size_limit: u64::min(new, self.size_limit),
            ..self
        }
    }

    pub fn set_remaining_secs(self, new: u64) -> Self {
        Capability {
            timeout: u64::min(
                u64::saturating_add(current_unix_timestamp(), new),
                self.timeout,
            ),
            ..self
        }
    }
}

impl serde::ser::Serialize for Capability {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        SerializableCapability::from(self).serialize(serializer)
    }
}

impl<'de> serde::de::Deserialize<'de> for Capability {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        SerializableCapability::deserialize(deserializer).map(|v| v.into())
    }
}
