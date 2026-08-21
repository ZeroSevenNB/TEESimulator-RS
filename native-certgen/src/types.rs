use crate::error::CertGenError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum Algorithm {
    Rsa = 1,
    Ec = 3,
}

impl TryFrom<i32> for Algorithm {
    type Error = CertGenError;
    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Rsa),
            3 => Ok(Self::Ec),
            _ => Err(CertGenError::UnsupportedAlgorithm(value)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum EcCurve {
    P224 = 0,
    P256 = 1,
    P384 = 2,
    P521 = 3,
    Curve25519 = 4,
}

impl TryFrom<i32> for EcCurve {
    type Error = CertGenError;
    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::P224),
            1 => Ok(Self::P256),
            2 => Ok(Self::P384),
            3 => Ok(Self::P521),
            4 => Ok(Self::Curve25519),
            _ => Err(CertGenError::UnsupportedEcCurve(value)),
        }
    }
}

pub struct CertGenParams {
    pub algorithm: Algorithm,
    pub key_size: u32,
    pub ec_curve: Option<EcCurve>,
    pub rsa_public_exponent: u64,

    pub attestation_challenge: Option<Vec<u8>>,
    pub purposes: Vec<i32>,
    pub digests: Vec<i32>,

    pub cert_serial: Option<Vec<u8>>,
    pub cert_subject: Option<Vec<u8>>,
    pub cert_not_before: i64,
    pub cert_not_after: i64,

    pub keybox_private_key: Vec<u8>,
    pub keybox_cert_chain: Vec<u8>,

    pub security_level: i32,
    pub attest_version: i32,
    pub keymaster_version: i32,

    pub os_version: i32,
    pub os_patch_level: i32,
    pub vendor_patch_level: i32,
    pub boot_patch_level: i32,

    pub boot_key: Vec<u8>,
    pub boot_hash: Vec<u8>,

    /// The INCLUDE_UNIQUE_ID digest, already computed by the Kotlin layer (HMAC-SHA256 over the
    /// temporal counter + attestation application id + 0x00, truncated to 16 bytes). `None` means the
    /// caller did not request INCLUDE_UNIQUE_ID, so the extension carries an empty uniqueId.
    pub unique_id: Option<Vec<u8>>,
    /// Whether the RootOfTrust reports the device locked. The Kotlin layer supplies the forged
    /// "locked" value for unlocked devices, so the Rust layer no longer hard-codes it.
    pub device_locked: bool,
    /// VerifiedBootState (0 Verified, 1 SelfSigned, 2 Unverified, 3 Failed) to report.
    pub verified_boot_state: i32,

    pub creation_datetime: i64,
    pub attestation_application_id: Vec<u8>,
    pub module_hash: Option<Vec<u8>>,

    pub id_brand: Option<Vec<u8>>,
    pub id_device: Option<Vec<u8>>,
    pub id_product: Option<Vec<u8>>,
    pub id_serial: Option<Vec<u8>>,
    pub id_imei: Option<Vec<u8>>,
    pub id_meid: Option<Vec<u8>>,
    pub id_manufacturer: Option<Vec<u8>>,
    pub id_model: Option<Vec<u8>>,
    pub id_second_imei: Option<Vec<u8>>,

    pub active_datetime: i64,
    pub origination_expire_datetime: i64,
    pub usage_expire_datetime: i64,
    pub usage_count_limit: i32,
    pub caller_nonce: bool,
    pub unlocked_device_required: bool,
    pub no_auth_required: bool,

    /// Calling app UID, used only to key diagnostic log lines to the requesting app.
    pub uid: i32,
    /// Mirrors the APK debug variant; gates the produced-extension dump so release stays quiet.
    pub debug_logging: bool,
}

pub struct GeneratedKeyPair {
    pub private_key_pkcs8: Vec<u8>,
}
