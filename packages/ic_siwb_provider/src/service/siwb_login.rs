use candid::{candid_method, Principal};
use ic_cdk::api::is_controller;
use ic_cdk::update;

use ic_siwb::login::{BtcSignature, LoginDetails, SignMessageType};
use ic_siwb::utils::get_script_from_address;
use ic_stable_structures::storable::Blob;
use serde_bytes::ByteBuf;

use crate::service::types::AddressScriptBuf;
use crate::{update_root_hash, ADDRESS_PRINCIPAL, PRINCIPAL_ADDRESS, SETTINGS, STATE};

/// Authenticates the user by verifying the signature of the SIWB message. This function also
/// prepares the delegation to be fetched in the next step, the `siwb_get_delegation` function.
///
/// # Arguments
/// * `signature` (String): The signature of the SIWB message.
/// * `address` (String): The Bitcoin address of the user.
/// * `session_key` (ByteBuf): A unique key that identifies the session.
///
/// # Returns
/// * `Ok(LoginOkResponse)`: Contains the user canister public key and other login response data if the login is successful.
/// * `Err(String)`: An error message if the login process fails.
#[update]
fn siwb_login(
    signature: String,
    address: String,
    public_key: String,
    session_key: ByteBuf,
    sign_message_type: SignMessageType,
) -> Result<LoginDetails, String> {
    STATE.with(|state| {
        let signature_map = &mut *state.signature_map.borrow_mut();

        // Create an BtcAddress from the string. This validates the address.
        let address = get_script_from_address(address)?;

        // Create an BtcSignature from the string. This validates the signature.
        let signature = BtcSignature(signature);

        // Attempt to log in with the provided signature, address, and session key.

        let login_response = ic_siwb::login::login(
            &signature,
            &address.address_raw,
            public_key,
            session_key,
            &mut *signature_map,
            &ic_cdk::api::id(),
            sign_message_type,
        )
        .map_err(|e| e.to_string())?;

        // Update the certified data of the canister due to changes in the signature map.
        update_root_hash(&state.asset_hashes.borrow(), signature_map);

        // Convert the user canister public key to a principal.
        let principal: Blob<29> =
            Principal::self_authenticating(&login_response.user_canister_pubkey).as_slice()[..29]
                .try_into()
                .map_err(|_| format!("Invalid principal: {:?}", login_response))?;

        // Store the mapping of principal to Bitcoin address and vice versa if the settings allow it.
        manage_principal_address_mappings(
            &principal,
            &AddressScriptBuf(address.script_buf.to_bytes()),
        );

        Ok(login_response)
    })
}

#[update(name = "prune_sigs", guard = "controller_guard")]
#[candid_method(update, rename = "prune_sigs")]
fn prune_sigs() {
    STATE.with(|state| {
        let signature_map = &mut *state.signature_map.borrow_mut();
        ic_siwb::login::prune_all(signature_map);
    })
}

fn manage_principal_address_mappings(principal: &Blob<29>, address: &AddressScriptBuf) {
    SETTINGS.with(|s| {
        if !s.borrow().disable_principal_to_btc_mapping {
            PRINCIPAL_ADDRESS.with(|pa| {
                pa.borrow_mut().insert(*principal, address.clone());
            });
        }
        if !s.borrow().disable_btc_to_principal_mapping {
            ADDRESS_PRINCIPAL.with(|ap| {
                ap.borrow_mut().insert(address.clone(), *principal);
            });
        }
    });
}

#[inline]
fn controller_guard() -> Result<(), String> {
    match is_controller(&ic_cdk::caller()) {
        true => Ok(()),
        false => {
            ic_cdk::api::trap("Only the controller can call this function");
        }
    }
}
