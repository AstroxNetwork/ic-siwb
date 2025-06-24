use crate::service::siwb_login::controller_guard;
use candid::{candid_method, CandidType, Principal};
use ic_cdk::{init, post_upgrade, update};
use ic_siwb::bitcoin::Network;
use ic_siwb::bitcoin::Network::Bitcoin;
use ic_siwb::settings::SettingsBuilder;
use serde::Deserialize;
use std::str::FromStr;

use crate::SETTINGS;

#[derive(CandidType, Debug, Clone, PartialEq, Deserialize)]
pub enum RuntimeFeature {
    // Include the app frontend URI as part of the identity seed.
    IncludeUriInSeed,

    // Disable the mapping of Bitcoin address to principal. This also disables canister endpoints `get_principal`.
    DisableBtcToPrincipalMapping,

    // Disable the mapping of principal to Bitcoin address. This also disables canister endpoints `get_address` and `get_caller_address`.
    DisablePrincipalToBtcMapping,
}

/// Represents the settings that determine the behavior of the SIWB library. It includes settings such as domain, scheme, statement,
/// and expiration times for sessions and sign-ins.
#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct SettingsInput {
    /// The full domain, including subdomains, from where the frontend that uses SIWB is served.
    /// Example: "example.com" or "sub.example.com".
    pub domain: String,

    /// The full URI, potentially including port number of the frontend that uses SIWB.
    /// Example: "https://example.com" or "https://sub.example.com:8080".
    pub uri: String,

    /// The salt is used when generating the seed that uniquely identifies each user principal. The salt can only contain
    /// printable ASCII characters.
    pub salt: String,

    /// The Bitcoin network ic-siwb, defaults to "bitcoin" (Bitcoin mainnet).
    pub network: Option<String>,

    // The scheme used to serve the frontend that uses SIWB. Defaults to "https".
    pub scheme: Option<String>,

    /// The statement is a message or declaration, often presented to the user by the Bitcoin wallet
    pub statement: Option<String>,

    /// The TTL for a sign-in message in nanoseconds. After this time, the sign-in message will be pruned.
    pub sign_in_expires_in: Option<u64>,

    /// The TTL for a session in nanoseconds.
    pub session_expires_in: Option<u64>,

    /// The list of canisters for which the identity delegation is allowed. Defaults to None, which means
    /// that the delegation is allowed for all canisters. If specified, the canister id of this canister must be in the list.
    pub targets: Option<Vec<String>>,

    pub runtime_features: Option<Vec<RuntimeFeature>>,
}

/// Initialize the SIWB library with the given settings.
///
/// Required fields are `domain`, `uri`, and `salt`. All other fields are optional.
///
/// ## 🛑 Important: Changing the `salt` or `uri` setting affects how user seeds are generated.
/// This means that existing users will get a new principal id when they sign in. Tip: Don't change the `salt` or `uri`
/// settings after users have started using the service!
fn siwb_init(settings_input: SettingsInput) {
    let mut ic_siwb_settings = SettingsBuilder::new(
        &settings_input.domain,
        &settings_input.uri,
        &settings_input.salt,
    );

    // Optional fields
    if let Some(chain_id) = settings_input.network {
        if let Ok(n) = Network::from_str(&chain_id) {
            ic_siwb_settings = ic_siwb_settings.network(n);
        } else {
            ic_siwb_settings = ic_siwb_settings.network(Bitcoin);
        }
    }
    if let Some(scheme) = settings_input.scheme {
        ic_siwb_settings = ic_siwb_settings.scheme(scheme);
    }
    if let Some(statement) = settings_input.statement {
        ic_siwb_settings = ic_siwb_settings.statement(statement);
    }
    if let Some(expire_in) = settings_input.sign_in_expires_in {
        ic_siwb_settings = ic_siwb_settings.sign_in_expires_in(expire_in);
    }
    if let Some(session_expire_in) = settings_input.session_expires_in {
        ic_siwb_settings = ic_siwb_settings.session_expires_in(session_expire_in);
    }
    if let Some(targets) = settings_input.targets {
        let targets: Vec<Principal> = targets
            .into_iter()
            .map(|t| Principal::from_text(t).unwrap())
            .collect();
        // Make sure the canister id of this canister is in the list of targets
        let canister_id = ic_cdk::id();
        if !targets.contains(&canister_id) {
            panic!(
                "ic_siwb_provider canister id {} not in the list of targets",
                canister_id
            );
        }
        ic_siwb_settings = ic_siwb_settings.targets(targets);
    }

    SETTINGS.with_borrow_mut(|provider_settings| {
        if let Some(runtime_features) = settings_input.runtime_features {
            for feature in runtime_features {
                match feature {
                    RuntimeFeature::IncludeUriInSeed => {
                        ic_siwb_settings = ic_siwb_settings.runtime_features(vec![
                            ic_siwb::settings::RuntimeFeature::IncludeUriInSeed,
                        ]);
                    }
                    RuntimeFeature::DisableBtcToPrincipalMapping => {
                        provider_settings.disable_btc_to_principal_mapping = true;
                    }
                    RuntimeFeature::DisablePrincipalToBtcMapping => {
                        provider_settings.disable_principal_to_btc_mapping = true;
                    }
                }
            }
        }

        // Build and initialize SIWB
        ic_siwb::init(ic_siwb_settings.build().unwrap()).unwrap();
    });
}

/// `init` is called when the canister is created. It initializes the SIWB library with the given settings.
///
/// Required fields are `domain`, `uri`, and `salt`. All other fields are optional.
///
/// ## 🛑 Important: Changing the `salt` or `uri` setting affects how user seeds are generated.
/// This means that existing users will get a new principal id when they sign in. Tip: Don't change the `salt` or `uri`
/// settings after users have started using the service!
#[init]
fn init(settings: SettingsInput) {
    siwb_init(settings);
}

/// `post_upgrade` is called when the canister is upgraded. It initializes the SIWB library with the given settings.
///
/// Required fields are `domain`, `uri`, and `salt`. All other fields are optional.
///
/// ## 🛑 Important: Changing the `salt` or `uri` setting affects how user seeds are generated.
/// This means that existing users will get a new principal id when they sign in. Tip: Don't change the `salt` or `uri`
/// settings after users have started using the service!
#[post_upgrade]
fn upgrade(settings: SettingsInput) {
    siwb_init(settings);
}

#[update(name = "update_settings", guard = "controller_guard")]
#[candid_method(update, rename = "update_settings")]
fn update_settings(settings: SettingsInput) {
    siwb_init(settings);
}
