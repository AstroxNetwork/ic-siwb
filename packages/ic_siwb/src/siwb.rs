use crate::settings::Settings;
use crate::with_settings;
use crate::{rand::generate_nonce, time::get_current_time};

use bitcoin::Address;
use candid::{CandidType, Deserialize};
use serde::Serialize;
use std::collections::HashMap;
use std::fmt;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

#[derive(Debug)]
pub enum SiwbMessageError {
    MessageNotFound,
}

impl fmt::Display for SiwbMessageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SiwbMessageError::MessageNotFound => write!(f, "Message not found"),
        }
    }
}

impl From<SiwbMessageError> for String {
    fn from(error: SiwbMessageError) -> Self {
        error.to_string()
    }
}

/// Represents a SIWB (Sign-In With Bitcoin) message.
///
/// This struct and its implementation methods support all required fields in the [ERC-4361](https://eips.ethereum.org/EIPS/eip-4361)
/// specification.
///
/// # Examples
///
/// The following is an example of a SIWB message formatted according to the [ERC-4361](https://eips.ethereum.org/EIPS/eip-4361) specification:
///
/// ```text
/// 127.0.0.1 wants you to sign in with your Bitcoin account:
/// bc1p....123
///
/// Login to the app
///
/// URI: http://127.0.0.1:5173
/// Version: 1
/// Chain ID: 10
/// Nonce: ee1ee5ead5b55fe8c8e9
/// Issued At: 2021-05-06T19:17:10Z
/// Expiration Time: 2021-05-06T19:17:13Z
/// ```
#[derive(CandidType, Deserialize, Serialize, Clone, Debug)]
pub struct SiwbMessage {
    pub scheme: String,
    pub domain: String,
    pub address: String,
    pub statement: String,
    pub uri: String,
    pub version: u8,
    pub network: String,
    pub nonce: String,
    pub issued_at: u64,
    pub expiration_time: u64,
}

impl SiwbMessage {
    /// Constructs a new `SiwbMessage` for a given Bitcoin address using the settings defined in the
    /// global [`Settings`] struct.
    ///
    /// # Arguments
    ///
    /// * `address`: The Bitcoin address of the user.
    ///
    /// # Returns
    ///
    /// A `Result` that, on success, contains a new [`SiwbMessage`] instance.
    pub fn new(address: &Address) -> SiwbMessage {
        let nonce = generate_nonce();
        let current_time = get_current_time();
        with_settings!(|settings: &Settings| {
            SiwbMessage {
                scheme: settings.scheme.clone(),
                domain: settings.domain.clone(),
                address: address.to_string(),
                statement: settings.statement.clone(),
                uri: settings.uri.clone(),
                version: 1,
                network: settings.network.to_string(),
                nonce,
                issued_at: get_current_time(),
                expiration_time: current_time.saturating_add(settings.sign_in_expires_in),
            }
        })
    }

    /// Checks if the SIWB message is currently valid.
    ///
    /// # Returns
    ///
    /// `true` if the message is within its valid time period, `false` otherwise.
    pub fn is_expired(&self) -> bool {
        let current_time = get_current_time();
        self.issued_at < current_time || current_time > self.expiration_time
    }
}

impl fmt::Display for SiwbMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let json = serde_json::to_string(self).map_err(|_| fmt::Error)?;
        write!(f, "{}", json)
    }
}

impl From<SiwbMessage> for String {
    /// Converts the SIWB message to the [ERC-4361](https://eips.ethereum.org/EIPS/eip-4361) string format.
    ///
    /// # Returns
    ///
    /// A string representation of the SIWB message in the ERC-4361 format.
    fn from(val: SiwbMessage) -> Self {
        let issued_at_datetime =
            OffsetDateTime::from_unix_timestamp_nanos(val.issued_at as i128).unwrap();
        let issued_at_iso_8601 = issued_at_datetime.format(&Rfc3339).unwrap();

        let expiration_datetime =
            OffsetDateTime::from_unix_timestamp_nanos(val.expiration_time as i128).unwrap();
        let expiration_iso_8601 = expiration_datetime.format(&Rfc3339).unwrap();

        format!(
            "{domain} wants you to sign in with your Bitcoin account:\n\
            {address}\n\n\
            {statement}\n\n\
            URI: {uri}\n\
            Version: {version}\n\
            Network: {network}\n\
            Nonce: {nonce}\n\
            Issued At: {issued_at_iso_8601}\n\
            Expiration Time: {expiration_iso_8601}",
            domain = val.domain,
            address = val.address,
            statement = val.statement,
            uri = val.uri,
            version = val.version,
            network = val.network,
            nonce = val.nonce,
        )
    }
}

/// The SiwbMessageMap is a map of SIWB messages keyed by the Bitcoin address of the user. SIWB messages
/// are stored in the map during the course of the login process and are removed once the login process
/// is complete. The map is also pruned periodically to remove expired SIWB messages.
pub struct SiwbMessageMap {
    map: HashMap<Vec<u8>, SiwbMessage>,
}

impl SiwbMessageMap {
    pub fn new() -> SiwbMessageMap {
        SiwbMessageMap {
            map: HashMap::new(),
        }
    }

    /// Removes SIWB messages that have exceeded their time to live.
    pub fn prune_expired(&mut self) {
        let current_time = get_current_time();
        self.map
            .retain(|_, message| message.expiration_time > current_time);
    }

    /// Adds a SIWB message to the map.
    pub fn insert(&mut self, address_bytes: Vec<u8>, message: SiwbMessage) {
        self.map.insert(address_bytes, message);
    }

    /// Returns a cloned SIWB message associated with the provided address or an error if the message
    /// does not exist.
    pub fn get(&self, address_bytes: &Vec<u8>) -> Result<SiwbMessage, SiwbMessageError> {
        self.map
            .get(address_bytes)
            .cloned()
            .ok_or(SiwbMessageError::MessageNotFound)
    }

    /// Removes the SIWB message associated with the provided address.
    pub fn remove(&mut self, address_bytes: &Vec<u8>) {
        self.map.remove(address_bytes);
    }

    pub fn clear(&mut self) {
        self.map.clear();
    }
}

impl Default for SiwbMessageMap {
    fn default() -> Self {
        Self::new()
    }
}
