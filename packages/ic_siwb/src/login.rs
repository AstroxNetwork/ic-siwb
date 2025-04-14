use std::collections::BTreeMap;
use std::fmt;
use std::mem::size_of;
use std::str::FromStr;

use base64::engine::general_purpose;
use base64::Engine;
use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::key::XOnlyPublicKey;
use bitcoin::psbt::{Prevouts, Psbt};
use bitcoin::script::Builder;
use bitcoin::script::Instruction::PushBytes;
use bitcoin::secp256k1::{Message, Secp256k1, ThirtyTwoByteHash};
use bitcoin::sighash::{EcdsaSighashType, SighashCache, TapSighashType};
use bitcoin::Network::{Bitcoin, Testnet};
use bitcoin::{
    secp256k1, Address, AddressType, Network, OutPoint, PublicKey as BitcoinPublicKey, Script,
    ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use byteorder::{ByteOrder, LittleEndian};
use candid::{CandidType, Deserialize, Principal};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use k256::sha2::digest::FixedOutput;
use k256::sha2::{Digest, Sha256};
use serde::Serialize;
use serde_bytes::ByteBuf;
use simple_asn1::ASN1EncodeErr;

use crate::error::BtcError;
use crate::error::BtcError::AddressTypeNotSupported;
use crate::hash::hash_bytes;
use crate::utils::{get_script_from_address, AddressInfo};
use crate::{
    delegation::{
        create_delegation, create_delegation_hash, create_user_canister_pubkey, generate_seed,
        DelegationError,
    },
    hash,
    settings::Settings,
    signature_map::SignatureMap,
    siwb::{SiwbMessage, SiwbMessageError},
    time::get_current_time,
    with_settings, SIWB_MESSAGES,
};

const MAX_SIGS_TO_PRUNE: usize = 10;
const MAGIC_BYTES: &str = "Bitcoin Signed Message:\n";

#[derive(CandidType, Clone, Serialize, Deserialize)]
pub enum SignMessageType {
    ECDSA,
    Bip322Simple,
}

pub struct BtcSignature(pub String);

/// This function is the first step of the user login process. It validates the provided Bitcoin address,
/// creates a SIWB message, saves it for future use, and returns it.
///
/// # Parameters
/// * `address`: A string slice (`&str`) representing the user's Bitcoin address. This address is
///   validated and used to create the SIWB message.
///
/// # Returns
/// A `Result` that, on success, contains the `SiwbMessage` for the user, or an error string on failure.
///
/// # Example
/// ```ignore
/// use ic_siwb::{
///   login::prepare_login,
/// };
///
/// let address = Address::from_str("bc1q....123").unwrap();
/// let message = prepare_login(&address).unwrap();
/// ```
pub fn prepare_login(address: &Address) -> Result<SiwbMessage, BtcError> {
    let message = SiwbMessage::new(address);

    // Save the SIWB message for use in the login call
    SIWB_MESSAGES.with_borrow_mut(|siwb_messages| {
        siwb_messages.insert(address.script_pubkey().to_bytes(), message.clone());
    });

    Ok(message)
}
/// Login details are returned after a successful login. They contain the expiration time of the
/// delegation and the user canister public key.
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct LoginDetails {
    /// The session expiration time in nanoseconds since the UNIX epoch. This is the time at which
    /// the delegation will no longer be valid.
    pub expiration: u64,

    /// The user canister public key. This key is used to derive the user principal.
    pub user_canister_pubkey: ByteBuf,
}

pub enum LoginError {
    BtcError(BtcError),
    SiwbMessageError(SiwbMessageError),
    AddressMismatch,
    DelegationError(DelegationError),
    ASN1EncodeErr(ASN1EncodeErr),
}

impl From<BtcError> for LoginError {
    fn from(err: BtcError) -> Self {
        LoginError::BtcError(err)
    }
}

impl From<SiwbMessageError> for LoginError {
    fn from(err: SiwbMessageError) -> Self {
        LoginError::SiwbMessageError(err)
    }
}

impl From<DelegationError> for LoginError {
    fn from(err: DelegationError) -> Self {
        LoginError::DelegationError(err)
    }
}

impl From<ASN1EncodeErr> for LoginError {
    fn from(err: ASN1EncodeErr) -> Self {
        LoginError::ASN1EncodeErr(err)
    }
}

impl fmt::Display for LoginError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoginError::BtcError(e) => write!(f, "{}", e),
            LoginError::SiwbMessageError(e) => write!(f, "{}", e),
            LoginError::AddressMismatch => write!(f, "Recovered address does not match"),
            LoginError::DelegationError(e) => write!(f, "{}", e),
            LoginError::ASN1EncodeErr(e) => write!(f, "{}", e),
        }
    }
}

/// Handles the second step of the user login process. It verifies the signature against the SIWB message,
/// creates a delegation for the session, adds it to the signature map, and returns login details
///
/// # Parameters
/// * `signature`: The SIWB message signature to verify.
/// * `address`: The Bitcoin address used to sign the SIWB message.
/// * `public_key`: The ecdsa public key of wallet, can retrieve from wallet provider
/// * `session_key`: A unique session key to be used for the delegation.
/// * `signature_map`: A mutable reference to `SignatureMap` to which the delegation hash will be added
///   after successful validation.
/// * `canister_id`: The principal of the canister performing the login.
///
/// # Returns
/// A `Result` that, on success, contains the [LoginDetails] with session expiration and user canister
/// public key, or an error string on failure.
pub fn login(
    signature: &BtcSignature,
    address: &Address,
    public_key: String,
    session_key: ByteBuf,
    signature_map: &mut SignatureMap,
    canister_id: &Principal,
    sign_message_type: SignMessageType,
) -> Result<LoginDetails, LoginError> {
    // Remove expired SIWB messages from the state before proceeding. The init settings determines
    // the time to live for SIWB messages.
    SIWB_MESSAGES.with_borrow_mut(|siwb_messages| {
        // Prune any expired SIWB messages from the state.
        siwb_messages.prune_expired();

        // Get the previously created SIWB message for current address. If it has expired or does not
        // exist, return an error.
        let address_bytes = address.script_pubkey().to_bytes();
        let message = siwb_messages.get(&address_bytes)?;
        let message_string: String = message.clone().into();

        // Verify the supplied signature against the SIWB message and recover the Bitcoin address
        // used to sign the message.

        match sign_message_type {
            SignMessageType::ECDSA => {
                let v = _verify_message(message_string, signature.0.clone(), public_key)
                    .map_err(|_| LoginError::AddressMismatch)?;

                if let Ok(addr) = verify_address(address.to_string().as_str(), v) {
                    if address.to_string() != addr {
                        return Err(LoginError::AddressMismatch);
                    }
                } else {
                    return Err(LoginError::AddressMismatch);
                }
            }
            SignMessageType::Bip322Simple => {
                let AddressInfo {
                    network,
                    address_type,
                    ..
                } = match get_script_from_address(address.to_string()) {
                    Ok(a) => a,
                    Err(_) => return Err(LoginError::AddressMismatch),
                };
                if address_type == AddressType::P2tr {
                    if !verify_signature_of_bip322_simple_p2tr(
                        address.to_string().as_str(),
                        message_string.as_str(),
                        signature.0.as_str(),
                        network,
                    ) {
                        return Err(LoginError::AddressMismatch);
                    }
                } else if address_type == AddressType::P2wpkh {
                    if !verify_signature_of_bip322_simple_segwitv0(
                        address.to_string().as_str(),
                        message_string.as_str(),
                        signature.0.as_str(),
                        network,
                    ) {
                        return Err(LoginError::AddressMismatch);
                    }
                } else {
                    return Err(LoginError::BtcError(AddressTypeNotSupported));
                }
            }
        }

        // At this point, the signature has been verified and the SIWB message has been used. Remove
        // the SIWB message from the state.
        siwb_messages.remove(&address_bytes);

        // The delegation is valid for the duration of the session as defined in the settings.
        let expiration = with_settings!(|settings: &Settings| {
            message
                .issued_at
                .saturating_add(settings.session_expires_in)
        });

        // The seed is what uniquely identifies the delegation. It is derived from the salt, the
        // Bitcoin address and the SIWB message URI.
        let seed = generate_seed(address);

        // Before adding the signature to the signature map, prune any expired signatures.
        signature_map.prune_expired(get_current_time(), MAX_SIGS_TO_PRUNE);

        // Create the delegation and add its hash to the signature map. The seed is used as the map key.
        let delegation = create_delegation(session_key, expiration)?;
        let delegation_hash = create_delegation_hash(&delegation);
        signature_map.put(hash::hash_bytes(seed), delegation_hash);

        // Create the user canister public key from the seed. From this key, the client can derive the
        // user principal.
        let user_canister_pubkey = create_user_canister_pubkey(canister_id, seed.to_vec())?;

        Ok(LoginDetails {
            expiration,
            user_canister_pubkey: ByteBuf::from(user_canister_pubkey),
        })
    })
}

pub fn prune_all(signature_map: &mut SignatureMap) {
    SIWB_MESSAGES.with_borrow_mut(|siwb_messages| {
        siwb_messages.clear();
        signature_map.prune_all();
    })
}

struct BufferWriter {}

impl BufferWriter {
    fn varint_buf_num(n: i64) -> Vec<u8> {
        let mut buf = Vec::new();
        if n < 253 {
            buf.push(n as u8);
        } else if n < 0x10000 {
            buf.push(253);
            let mut bytes = [0u8; size_of::<u16>()];
            LittleEndian::write_u16(&mut bytes, n as u16);
            buf.extend_from_slice(&bytes);
        } else if n < 0x100000000 {
            buf.push(254);
            let mut bytes = [0u8; size_of::<u32>()];
            LittleEndian::write_u32(&mut bytes, n as u32);
            buf.extend_from_slice(&bytes);
        } else {
            buf.push(255);
            let mut bytes = [0u8; size_of::<u64>()];
            LittleEndian::write_i32(&mut bytes[0..4], (n & -1) as i32);
            LittleEndian::write_u32(&mut bytes[4..8], (n / 0x100000000) as u32);
            buf.extend_from_slice(&bytes);
        }
        buf
    }
}

pub fn _msg_hash(message: String) -> Vec<u8> {
    let prefix1 = BufferWriter::varint_buf_num(MAGIC_BYTES.len() as i64);
    let message_buffer = message.as_bytes().to_vec();
    let prefix2 = BufferWriter::varint_buf_num(message_buffer.len() as i64);
    let mut buf = Vec::new();
    buf.extend_from_slice(&prefix1);
    buf.extend_from_slice(MAGIC_BYTES.as_bytes());
    buf.extend_from_slice(&prefix2);
    buf.extend_from_slice(&message_buffer);

    let _hash = Sha256::new_with_prefix(buf);
    let hash = Sha256::new_with_prefix(_hash.finalize_fixed().to_vec());
    return hash.finalize_fixed().to_vec();
}

fn _verify_message(
    message: String,
    signature: String,
    public_key: String,
) -> Result<Vec<u8>, String> {
    let message_prehashed = _msg_hash(message);
    let signature_bytes = general_purpose::STANDARD
        .decode(signature)
        .map_err(|_| "Invalid b64 signature".to_string())?;
    let public_key_bytes = hex::decode(public_key).map_err(|_| "Invalid public key".to_string())?;
    let recovered_public_key = recover_pub_key_compact(
        signature_bytes.as_slice(),
        message_prehashed.as_slice(),
        None,
    )?;

    return if public_key_bytes.clone() != recovered_public_key.clone() {
        Err("public_key_bytes != recovered_public_key".to_string())
    } else {
        Ok(recovered_public_key.clone())
    };
}

pub fn recover_pub_key_compact(
    signature_bytes: &[u8],
    message_hash: &[u8],
    chain_id: Option<u8>,
) -> Result<Vec<u8>, String> {
    let mut v;
    let r: Vec<u8> = signature_bytes[1..33].to_vec();
    let mut s: Vec<u8> = signature_bytes[33..65].to_vec();

    if signature_bytes.len() >= 65 {
        v = signature_bytes[0];
    } else {
        v = signature_bytes[33] >> 7;
        s[0] &= 0x7f;
    };
    if v < 27 {
        v = v + 27;
    }

    let mut bytes = [0u8; 65];
    if r.len() > 32 || s.len() > 32 {
        return Err("Cannot create secp256k1 signature: malformed signature.".to_string());
    }
    let rid = calculate_sig_recovery(v.clone(), chain_id);
    bytes[0..32].clone_from_slice(&r);
    bytes[32..64].clone_from_slice(&s);
    bytes[64] = rid;

    if rid > 3 {
        return Err(format!(
            "Cannot create secp256k1 signature: invalid recovery id. {:?}",
            rid
        ));
    }

    let recovery_id = RecoveryId::try_from(bytes[64]).map_err(|_| BtcError::InvalidRecoveryId)?;

    let signature = Signature::from_slice(&bytes[..64]).map_err(|_| BtcError::InvalidSignature)?;

    let verifying_key = VerifyingKey::recover_from_prehash(&message_hash, &signature, recovery_id)
        .map_err(|_| BtcError::PublicKeyRecoveryFailure)?;

    Ok(verifying_key.to_encoded_point(true).to_bytes().to_vec())
}

pub fn msg_hash(message: String) -> Vec<u8> {
    _msg_hash(message)
}

pub fn calculate_sig_recovery(mut v: u8, chain_id: Option<u8>) -> u8 {
    if v == 0 || v == 1 {
        return v;
    }

    return if chain_id.is_none() {
        v = v - 27;
        while v > 3 {
            v = v - 4;
        }
        v
    } else {
        v = v - (chain_id.unwrap() * 2 + 35);
        while v > 3 {
            v = v - 4;
        }
        v
    };
}

pub fn verify_address(address: &str, pub_bytes: Vec<u8>) -> Result<String, String> {
    let public_key =
        BitcoinPublicKey::from_slice(pub_bytes.as_slice()).map_err(|e| e.to_string())?;
    let secp = Secp256k1::verification_only();
    let mut network = Bitcoin;
    let mut address_type = AddressType::P2tr;

    if address.starts_with("bc1q") {
        address_type = AddressType::P2wpkh;
        network = Bitcoin;
    } else if address.starts_with("bc1p") {
        address_type = AddressType::P2tr;
        network = Bitcoin;
    } else if address.starts_with('1') {
        address_type = AddressType::P2pkh;
        network = Bitcoin;
    } else if address.starts_with('3') {
        address_type = AddressType::P2sh;
        network = Bitcoin;
    } else if address.starts_with("tb1q") {
        address_type = AddressType::P2wpkh;
        network = Testnet;
    } else if address.starts_with('m') || address.starts_with('n') {
        address_type = AddressType::P2pkh;
        network = Testnet;
    } else if address.starts_with('2') {
        address_type = AddressType::P2sh;
        network = Testnet;
    } else if address.starts_with("tb1p") {
        address_type = AddressType::P2tr;
        network = Testnet;
    }
    let compressed = if !public_key.compressed {
        BitcoinPublicKey::from_slice(&public_key.inner.serialize())
            .map_err(|e| e.to_string())
            .clone()?
    } else {
        public_key
    };

    match address_type {
        AddressType::P2pkh => {
            let p2pkh_address = Address::p2pkh(&public_key, network);
            Ok(p2pkh_address.to_string())
        }
        AddressType::P2wpkh => {
            let p2wpkh_address =
                Address::p2wpkh(&compressed, network).map_err(|e| e.to_string())?;
            Ok(p2wpkh_address.to_string())
        }
        AddressType::P2sh => {
            let p2sh_address =
                Address::p2shwpkh(&compressed, network).map_err(|e| e.to_string())?;
            Ok(p2sh_address.to_string())
        }
        AddressType::P2tr => {
            let internal_key = XOnlyPublicKey::from_slice(pub_bytes[1..].to_vec().as_slice())
                .map_err(|e| e.to_string())?;
            Ok(Address::p2tr(&secp, internal_key, None, network).to_string())
        }
        _ => Err("Unknown Address".to_string()),
    }
}

fn get_output_script_from_address(address: &str, network: Network) -> ScriptBuf {
    let _address = Address::from_str(address).unwrap();
    _address.require_network(network).unwrap().script_pubkey()
}

fn bip0322_hash(message: &str) -> Vec<u8> {
    let tag = "BIP0322-signed-message";
    let tag_hash = hash_bytes(tag.as_bytes());
    let mut hasher = Sha256::new();
    hasher.update(&tag_hash);
    hasher.update(&tag_hash);
    hasher.update(message.as_bytes());
    hasher.finalize().to_vec()
}

fn bip0322_tx(message_slice: &[u8], output_script: ScriptBuf) -> Transaction {
    // Prepare the transaction to spend
    let prevout_hash = vec![0u8; 32];
    let prevout_index = 0xffffffff;
    let sequence = Sequence(0);
    let mut slice = vec![];
    slice.extend_from_slice(&[0x00, 0x20]);
    slice.extend_from_slice(message_slice);

    let script_sig = ScriptBuf::from_bytes(slice);

    let tx_to_spend = Transaction {
        version: 0,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_slice(prevout_hash.as_slice()).unwrap(),
                vout: prevout_index,
            },
            script_sig: script_sig.clone(),
            sequence,
            witness: Witness::default(),
        }],
        output: vec![TxOut {
            value: 0,
            script_pubkey: output_script.clone(),
        }],
    };
    let tx_unsigned = bip0322_psbt_unsigned(tx_to_spend);
    tx_unsigned
}

fn bip0322_psbt_unsigned(tx_to_spend: Transaction) -> Transaction {
    Transaction {
        version: 0,
        lock_time: LockTime::from_height(0u32).unwrap(),
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: tx_to_spend.txid(), //Txid::from_slice(tx_bytes.as_slice()).unwrap(),
                vout: 0,
            },
            script_sig: Default::default(),
            sequence: Sequence::ZERO,
            witness: Witness::default(), //Witness::from(vec![data]),
        }],
        output: vec![TxOut {
            value: 0,
            script_pubkey: Builder::new()
                .push_opcode(bitcoin::blockdata::opcodes::all::OP_RETURN)
                .into_script(),
        }],
    }
}

fn verify_signature_of_bip322_simple_p2tr(
    address: &str,
    msg: &str,
    sig: &str,
    network: Network,
) -> bool {
    let secp = Secp256k1::new();
    let output_script = get_output_script_from_address(address.to_string().as_str(), network);
    let _tx = bip0322_tx(bip0322_hash(msg).as_slice(), output_script.clone());

    // Decode the signature
    let data = match general_purpose::STANDARD.decode(sig) {
        Ok(d) => d,
        Err(_) => return false,
    };

    let script_buf = ScriptBuf::from_bytes(data[1..].to_vec());

    let signature = match secp256k1::schnorr::Signature::from_slice(&script_buf.to_bytes()[1..]) {
        Ok(sig) => sig,
        Err(_) => return false,
    };

    let mut b = vec![];
    b.extend_from_slice(&output_script.to_bytes()[2..]);

    // Extract the public key from the address
    let pubkey = match XOnlyPublicKey::from_slice(b.as_slice()) {
        Ok(key) => key,
        Err(_) => return false,
    };

    // Prepare the PSBT to sign
    let mut psbt_to_sign = match Psbt::from_unsigned_tx(_tx) {
        Ok(psbt) => psbt,
        Err(_) => return false,
    };
    psbt_to_sign.version = 0;
    psbt_to_sign.inputs[0].tap_internal_key = Some(pubkey);
    let binding = [TxOut {
        value: 0,
        script_pubkey: output_script.clone(),
    }];
    let prevouts_all = Prevouts::All(&binding);

    let mut cache = SighashCache::new(&mut psbt_to_sign.unsigned_tx);
    let sighash = cache.taproot_key_spend_signature_hash(0, &prevouts_all, TapSighashType::Default);
    match sighash {
        Ok(sighash) => {
            let message = match Message::from_slice(&sighash.into_32()) {
                Ok(m) => m,
                Err(_) => return false,
            };
            secp.verify_schnorr(&signature, &message, &pubkey).is_ok()
        }
        Err(_) => false,
    }
}

fn verify_signature_of_bip322_simple_segwitv0(
    address: &str,
    msg: &str,
    sig: &str,
    network: Network,
) -> bool {
    let secp = Secp256k1::new();
    let output_script = get_output_script_from_address(address.to_string().as_str(), network);
    let _tx = bip0322_tx(bip0322_hash(msg).as_slice(), output_script.clone());

    // process signature, create partial_sig for segwit_v0
    let _data = match general_purpose::STANDARD.decode(sig) {
        Ok(data) => data,
        Err(_) => return false,
    };

    let script_buf = ScriptBuf::from_bytes(_data[1..].to_vec());

    let _res = match extract_bytes_from_script(&script_buf, 2) {
        Ok(d) => d.clone(),
        Err(_) => return false,
    };
    let sig = match bitcoin::ecdsa::Signature::from_slice(&_res[0]) {
        Ok(sig) => sig,
        Err(_) => return false,
    };
    let pubkey = match bitcoin::key::PublicKey::from_slice(&_res[1]) {
        Ok(key) => key,
        Err(_) => return false,
    };
    let mut partial_sig = BTreeMap::new();
    partial_sig.insert(pubkey, sig);

    // Prepare the PSBT to sign
    let mut psbt_to_sign = match Psbt::from_unsigned_tx(_tx) {
        Ok(psbt) => psbt,
        Err(_) => return false,
    };
    psbt_to_sign.version = 0;
    psbt_to_sign.inputs[0].partial_sigs = partial_sig;
    psbt_to_sign.inputs[0].witness_utxo = Some(TxOut {
        value: 0,
        script_pubkey: output_script.clone(),
    });

    // verify every partial sigs to each input
    let ret = psbt_to_sign.inputs.iter().enumerate().all(|(i, input)| {
        input.partial_sigs.iter().all(|(pubkey, signature)| {
            let mut cache = SighashCache::new(&mut psbt_to_sign.unsigned_tx);
            match output_script.p2wpkh_script_code() {
                Some(code) => match cache.segwit_signature_hash(i, &code, 0, EcdsaSighashType::All)
                {
                    Ok(sighash) => Message::from_slice(&sighash.into_32())
                        .map(|message| {
                            secp.verify_ecdsa(&message, &signature.sig, &pubkey.inner)
                                .is_ok()
                        })
                        .unwrap_or(true),
                    Err(_) => false,
                },
                None => false,
            }
        })
    });

    return ret;
}

fn extract_bytes_from_script(script: &Script, expect_size: usize) -> Result<Vec<Vec<u8>>, String> {
    if script.instructions().count() != expect_size {
        return Err("Invalid script size".to_string());
    }
    let mut payload = vec![];
    let instructions = script.instructions().peekable();
    instructions
        .into_iter()
        .for_each(|instruction| match instruction {
            Ok(PushBytes(bytes)) => payload.push(bytes.as_bytes().to_vec()),
            _ => {
                println!("instruction is {:?}", instruction);
            }
        });
    Ok(payload)
}

#[cfg(test)]
mod test {
    use crate::login::{
        _verify_message, bip0322_hash, verify_address, verify_signature_of_bip322_simple_p2tr,
        verify_signature_of_bip322_simple_segwitv0,
    };

    #[test]
    fn test_get_address() {
        let p2tr_t = verify_address(
            "tb1pgvdp7lf89d62zadds5jvyjntxmr7v70yv33g7vqaeu2p0cuexveqjlwphr",
            hex::decode("03133c85d348d6c0796382966380719397453592e706cd3329119a2d2cb8d2ff7b")
                .unwrap(),
        );
        let p2tr = verify_address(
            "bc1pgvdp7lf89d62zadds5jvyjntxmr7v70yv33g7vqaeu2p0cuexveq9hcwdv",
            hex::decode("03133c85d348d6c0796382966380719397453592e706cd3329119a2d2cb8d2ff7b")
                .unwrap(),
        );
        assert_eq!(
            p2tr_t.unwrap(),
            "tb1pgvdp7lf89d62zadds5jvyjntxmr7v70yv33g7vqaeu2p0cuexveqjlwphr".to_string()
        );
        assert_eq!(
            p2tr.unwrap(),
            "bc1pgvdp7lf89d62zadds5jvyjntxmr7v70yv33g7vqaeu2p0cuexveq9hcwdv".to_string()
        );

        let p2shp2wpkh_t = verify_address(
            "2NBbnaYUvZvrvKfd7wqMmt7bZoAMTSkAarU",
            hex::decode("02e203c98d766554bb4dab431d70b014b505aac66f47b735d9e7cbb4f12108ac3d")
                .unwrap(),
        );
        let p2shp2wpkh = verify_address(
            "3L3aWoYtxUMa7szaGhjuGAcJap9Hb13EEP",
            hex::decode("02e203c98d766554bb4dab431d70b014b505aac66f47b735d9e7cbb4f12108ac3d")
                .unwrap(),
        );
        assert_eq!(
            p2shp2wpkh_t.unwrap(),
            "2NBbnaYUvZvrvKfd7wqMmt7bZoAMTSkAarU".to_string()
        );
        assert_eq!(
            p2shp2wpkh.unwrap(),
            "3L3aWoYtxUMa7szaGhjuGAcJap9Hb13EEP".to_string()
        );

        let p2wpkh_t = verify_address(
            "tb1qshqyem2rf8jyla904gd2cvek2k8nz5z3vc2j3x",
            hex::decode("03f72a781776c63888aa9af5478c72c4794165a44024679995f6d232b4f6254574")
                .unwrap(),
        );
        let p2wpkh = verify_address(
            "bc1qshqyem2rf8jyla904gd2cvek2k8nz5z3x73p24",
            hex::decode("03f72a781776c63888aa9af5478c72c4794165a44024679995f6d232b4f6254574")
                .unwrap(),
        );
        assert_eq!(
            p2wpkh_t.unwrap(),
            "tb1qshqyem2rf8jyla904gd2cvek2k8nz5z3vc2j3x".to_string()
        );
        assert_eq!(
            p2wpkh.unwrap(),
            "bc1qshqyem2rf8jyla904gd2cvek2k8nz5z3x73p24".to_string()
        );

        let p2pkh_t = verify_address(
            "mt1ycNxRhKVf1JyHhrKQEuuMoBnSPrwxfM",
            hex::decode("03133c85d348d6c0796382966380719397453592e706cd3329119a2d2cb8d2ff7b")
                .unwrap(),
        );
        let p2pkh = verify_address(
            "1DW2KKsStJ4QECVfzHM2Qzh2wCBjTe9TH1",
            hex::decode("03133c85d348d6c0796382966380719397453592e706cd3329119a2d2cb8d2ff7b")
                .unwrap(),
        );
        assert_eq!(
            p2pkh_t.unwrap(),
            "mt1ycNxRhKVf1JyHhrKQEuuMoBnSPrwxfM".to_string()
        );
        assert_eq!(
            p2pkh.unwrap(),
            "1DW2KKsStJ4QECVfzHM2Qzh2wCBjTe9TH1".to_string()
        );
    }
    #[test]
    fn test_message() {
        let p = "03133c85d348d6c0796382966380719397453592e706cd3329119a2d2cb8d2ff7b".to_string();
        let s =  "HPVVoaHfyCUER9YB6MC8C+eh3in24rHTScQopgwzzEx6GP9fwZBI+ZIesS1HNzbMzMgLFS10IyhMc6aYbn3zfI4=".to_string();
        let m = "{\"a\":1,\"b\":[2,3,4]}".to_string();
        let a = "tb1pgvdp7lf89d62zadds5jvyjntxmr7v70yv33g7vqaeu2p0cuexveqjlwphr".to_string();

        let v = _verify_message(m, s, p);
        println!("v is {:?}", v);

        let v2 = verify_address(a.as_str(), v.unwrap());
        println!("v2 is {:?}", v2);
    }

    #[test]
    fn test_bip322_messasge() {
        let m = "hello".to_string();
        let h = bip0322_hash(m.as_str());
        println!("hash is {:?}", hex::encode(h.clone()));
        assert_eq!(
            hex::encode(h.clone()),
            "528e990bccf82644773d67eff12fb504e84b42c8396475da8c939404f4a32385".to_string()
        );
    }

    #[test]
    fn test_bip322_verify_p2tr() {
        let m = "hello".to_string();
        let a = "tb1phy4ay0kvcnelc9trqzk4ksld3qx45gm83274qxp204vzycg7hxaq2m2nrn".to_string();
        let s = "AUBNN/m5COckJE1nj5bR9iAO+Ga5VlJU2xIIGBraFZQNDUtOO0J0tOhoQzvk0o+YwknQ3OGWyWR5VwiG2KzJwjUV".to_string();

        let v = verify_signature_of_bip322_simple_p2tr(
            a.as_str(),
            m.as_str(),
            s.as_str(),
            bitcoin::Network::Testnet,
        );
        assert_eq!(v, true)
    }

    #[test]
    fn test_bip322_verify_p2pkwh() {
        let m = "hello".to_string();
        let a = "tb1qf620ch70a2evf2n2jrmdk85wwpupx8qcszr2s7".to_string();
        let s = "AkgwRQIhAOh1XvCVjPhJbc6oELxiRjjavkOW9ebYC5gzepzjWhn0AiAPpoXFwjozO82PYiSGlnc9RoM9JknaFt5OhmrGD/J58AEhA89jkK3c5cXYcnPiBLRTC27FwKz4mzOrZ+rizCQnR/jj".to_string();

        let v = verify_signature_of_bip322_simple_segwitv0(
            a.as_str(),
            m.as_str(),
            s.as_str(),
            bitcoin::Network::Testnet,
        );
        assert_eq!(v, true);
    }
}
