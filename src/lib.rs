use std::mem;

pub const TPM2_SHA_DIGEST_SIZE: u32 = 20;
pub const TPM2_SHA1_DIGEST_SIZE: u32 = 20;
pub const TPM2_SHA256_DIGEST_SIZE: u32 = 32;
pub const TPM2_SHA384_DIGEST_SIZE: u32 = 48;
pub const TPM2_SHA512_DIGEST_SIZE: u32 = 64;
pub const TPM2_SM3_256_DIGEST_SIZE: u32 = 32;

pub const TPM2_MAX_DIGEST_BUFFER: u32 = 1024;
pub const TPM2_MAX_NV_BUFFER_SIZE: u32 = 2048;
pub const TPM2_MAX_CAP_BUFFER: u32 = 1024;
pub const TPM2_NUM_PCR_BANKS: u32 = 16;
pub const TPM2_MAX_PCRS: u32 = 32;
pub const TPM2_PCR_SELECT_MAX: u32 = (TPM2_MAX_PCRS + 7) / 8;
pub const TPM2_LABEL_MAX_BUFFER: u32 = 32;

/* Encryption block sizes */
pub const TPM2_MAX_SYM_BLOCK_SIZE: u32 = 16;
pub const TPM2_MAX_SYM_DATA: u32 = 256;
pub const TPM2_MAX_ECC_KEY_BYTES: u32 = 128;
pub const TPM2_MAX_SYM_KEY_BYTES: u32 = 32;
pub const TPM2_MAX_RSA_KEY_BYTES: u32 = 512;

pub const TPM2_PRIVATE_VENDOR_SPECIFIC_BYTES: u32 = (TPM2_MAX_RSA_KEY_BYTES / 2) * (3 + 2);

pub const TPM2_MAX_CONTEXT_SIZE: u32 = 5120;

pub type TpmaLocality = u8;

pub type Tpm2AlgId = u16;
pub type Tpm2KeyBits = u16;
pub type Tpm2St = u16;

pub type Tpm2Generated = u32;
pub type Tpm2Handle = u32;
pub type Tpm2Rc = u32;
pub type TpmaNv = u32;

pub type TpmiAlgHash = Tpm2AlgId;
pub type TpmiAlgKdf = Tpm2AlgId;
pub type TpmiAlgPublic = Tpm2AlgId;
pub type TpmiAlgSymMode = Tpm2AlgId;
pub type TpmiAlgSymObject = Tpm2AlgId;
pub type TpmiAlgKeyedhashScheme = Tpm2AlgId;
pub type TpmiAlgRsaScheme = Tpm2AlgId;
pub type TpmiAlgEccScheme = Tpm2AlgId;
pub type TpmiAlgAsymScheme = Tpm2AlgId;

pub type TpmiRhNvIndex = Tpm2Handle;

pub type Tpm2EccCurve = u16;
pub type TpmiEccCurve = Tpm2EccCurve;

pub type TpmiYesNo = u8;
pub type TpmiStAttest = Tpm2St;

pub type TpmiAesKeyBits = Tpm2KeyBits;
pub type TpmiSm4KeyBits = Tpm2KeyBits;
pub type TpmiCamelliaKeyBits = Tpm2KeyBits;
pub type TpmiRsaKeyBits = Tpm2KeyBits;

pub type TpmaObject = u32;

pub type Tss2Rc = Tpm2Rc;

pub mod error_codes {
    use crate::Tss2Rc;

    pub const TSS2_RC_LAYER_SHIFT: u32 = 16;
    pub const TSS2_RC_LAYER_MASK: Tss2Rc = 0xFF << TSS2_RC_LAYER_SHIFT;
    pub const TSS2_MU_RC_LAYER: Tss2Rc = 9 << TSS2_RC_LAYER_SHIFT;

    pub const TSS2_BASE_RC_GENERAL_FAILURE: Tss2Rc = 1;
    pub const TSS2_BASE_RC_NOT_IMPLEMENTED: Tss2Rc = 2;
    pub const TSS2_BASE_RC_BAD_CONTEXT: Tss2Rc = 3;
    pub const TSS2_BASE_RC_ABI_MISMATCH: Tss2Rc = 4;
    pub const TSS2_BASE_RC_BAD_REFERENCE: Tss2Rc = 5;
    pub const TSS2_BASE_RC_INSUFFICIENT_BUFFER: Tss2Rc = 6;
    pub const TSS2_BASE_RC_BAD_SEQUENCE: Tss2Rc = 7;
    pub const TSS2_BASE_RC_NO_CONNECTION: Tss2Rc = 8;
    pub const TSS2_BASE_RC_TRY_AGAIN: Tss2Rc = 9;
    pub const TSS2_BASE_RC_IO_ERROR: Tss2Rc = 10;
    pub const TSS2_BASE_RC_BAD_VALUE: Tss2Rc = 11;
    pub const TSS2_BASE_RC_NOT_PERMITTED: Tss2Rc = 12;
    pub const TSS2_BASE_RC_INVALID_SESSIONS: Tss2Rc = 13;
    pub const TSS2_BASE_RC_NO_DECRYPT_PARAM: Tss2Rc = 14;
    pub const TSS2_BASE_RC_NO_ENCRYPT_PARAM: Tss2Rc = 15;
    pub const TSS2_BASE_RC_BAD_SIZE: Tss2Rc = 16;
    pub const TSS2_BASE_RC_MALFORMED_RESPONSE: Tss2Rc = 17;
    pub const TSS2_BASE_RC_INSUFFICIENT_CONTEXT: Tss2Rc = 18;
    pub const TSS2_BASE_RC_INSUFFICIENT_RESPONSE: Tss2Rc = 19;

    pub const TSS2_MU_RC_INSUFFICIENT_BUFFER: Tss2Rc =
        TSS2_MU_RC_LAYER | TSS2_BASE_RC_INSUFFICIENT_BUFFER;
    pub const TSS2_MU_RC_BAD_SIZE: Tss2Rc = TSS2_MU_RC_LAYER | TSS2_BASE_RC_BAD_SIZE;
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct TpmsEmpty;

#[repr(C)]
#[derive(Clone, Copy)]
pub union TpmuHa {
    sha: [u8; TPM2_SHA_DIGEST_SIZE as usize],
    sha1: [u8; TPM2_SHA1_DIGEST_SIZE as usize],
    sha256: [u8; TPM2_SHA256_DIGEST_SIZE as usize],
    sha384: [u8; TPM2_SHA384_DIGEST_SIZE as usize],
    sha512: [u8; TPM2_SHA512_DIGEST_SIZE as usize],
    sm3_256: [u8; TPM2_SM3_256_DIGEST_SIZE as usize],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TpmtHa {
    pub hash_alg: TpmiAlgHash,
    pub digest: TpmuHa,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union TpmuName {
    pub digest: TpmtHa,
    pub handle: Tpm2Handle,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bDigest {
    size: u16,
    pub buffer: [u8; mem::size_of::<TpmuHa>()],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bData {
    size: u16,
    pub buffer: [u8; mem::size_of::<TpmuHa>()],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bEvent {
    size: u16,
    pub buffer: [u8; 1024],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bMaxBuffer {
    size: u16,
    pub buffer: [u8; TPM2_MAX_DIGEST_BUFFER as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bMaxNvBuffer {
    size: u16,
    pub buffer: [u8; TPM2_MAX_NV_BUFFER_SIZE as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bIv {
    size: u16,
    pub buffer: [u8; TPM2_MAX_SYM_BLOCK_SIZE as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bName {
    size: u16,
    pub name: [u8; mem::size_of::<TpmuName>()],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bMaxCapBuffer {
    size: u16,
    pub buffer: [u8; TPM2_MAX_CAP_BUFFER as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct TpmsClockInfo {
    pub clock: u64,
    pub reset_count: u32,
    pub restart_count: u32,
    pub safe: TpmiYesNo,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct TpmsPcrSelection {
    pub hash: TpmiAlgHash,
    pub sizeof_select: u8,
    pub pcr_select: [u8; TPM2_PCR_SELECT_MAX as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct TpmlPcrSelection {
    pub count: u32,
    pub pcr_selections: [TpmsPcrSelection; TPM2_NUM_PCR_BANKS as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct TpmsQuoteInfo {
    pub pcr_select: TpmlPcrSelection,
    pub pcr_digest: Tpm2bDigest,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct TpmsCreationInfo {
    pub object_name: Tpm2bName,
    pub creation_hash: Tpm2bDigest,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct TpmsCertifyInfo {
    pub name: Tpm2bName,
    pub qualified_name: Tpm2bName,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct TpmsCommandAuditInfo {
    pub audit_counter: u64,
    pub digest_alg: Tpm2AlgId,
    pub audit_digest: Tpm2bDigest,
    pub command_digest: Tpm2bDigest,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct TpmsSessionAuditInfo {
    pub exclusive_session: TpmiYesNo,
    pub session_digest: Tpm2bDigest,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct TpmsTimeInfo {
    pub time: u64,
    pub clock_info: TpmsClockInfo,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct TpmsTimeAttestInfo {
    pub time: TpmsTimeInfo,
    pub firmware_version: u64,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct TpmsNvCertifyInfo {
    pub index_name: Tpm2bName,
    pub offset: u16,
    pub nv_contents: Tpm2bMaxNvBuffer,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union TPMU_ATTEST {
    pub certify: TpmsCertifyInfo,
    pub creation: TpmsCreationInfo,
    pub quote: TpmsQuoteInfo,
    pub command_audit: TpmsCommandAuditInfo,
    pub session_audit: TpmsSessionAuditInfo,
    pub time: TpmsTimeAttestInfo,
    pub nv: TpmsNvCertifyInfo,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TpmsAttest {
    pub magic: Tpm2Generated,
    pub tipe: TpmiStAttest, /* type is a reserved word, rename to tipe */
    pub qualified_signer: Tpm2bName,
    pub extra_data: Tpm2bData,
    pub clock_info: TpmsClockInfo,
    pub firmware_version: u64,
    pub attested: TPMU_ATTEST,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bAttest {
    size: u16,
    pub attestation_data: [u8; mem::size_of::<TpmsAttest>()],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bSymKey {
    size: u16,
    pub buffer: [u8; TPM2_MAX_SYM_KEY_BYTES as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bLabel {
    size: u16,
    pub buffer: [u8; TPM2_LABEL_MAX_BUFFER as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct TpmsDerive {
    pub label: Tpm2bLabel,
    pub context: Tpm2bLabel,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bDerive {
    size: u16,
    pub buffer: [u8; mem::size_of::<TpmsDerive>()],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union TpmuSensitiveCreate {
    pub create: [u8; TPM2_MAX_SYM_DATA as usize],
    pub derive: TpmsDerive
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bSensitiveData {
    size: u16,
    pub buffer: [u8; mem::size_of::<TpmuSensitiveCreate>()],
}

pub type Tpm2bAuth = Tpm2bDigest;

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct TpmsSensitiveCreate {
    pub user_auth: Tpm2bAuth,
    pub data: Tpm2bSensitiveData,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bSensitiveCreate {
    size: u16,
    pub sensitive: [u8; mem::size_of::<TpmsSensitiveCreate>()],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bPublicKeyRsa {
    size: u16,
    pub buffer: [u8; TPM2_MAX_RSA_KEY_BYTES as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bPrivateKeyRsa {
    size: u16,
    pub buffer: [u8; (TPM2_MAX_RSA_KEY_BYTES / 2) as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bEccParameter {
    size: u16,
    pub buffer: [u8; TPM2_MAX_ECC_KEY_BYTES as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct TpmsEccPoint {
    pub x: Tpm2bEccParameter,
    pub y: Tpm2bEccParameter,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bEccPoint {
    size: u16,
    pub point: [u8; mem::size_of::<TpmsEccPoint>()],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union TpmuEncryptedSecret {
    pub ecc: [u8; mem::size_of::<TpmsEccPoint>()],
    pub rsa: [u8; TPM2_MAX_RSA_KEY_BYTES as usize],
    pub symmetric: [u8; mem::size_of::<Tpm2bDigest>()],
    pub keyed_hash: [u8; mem::size_of::<Tpm2bDigest>()],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bEncryptedSecret {
    size: u16,
    pub secret: [u8; mem::size_of::<TpmuEncryptedSecret>()],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct TpmsSchemeXor {
    pub hash_alg: TpmiAlgHash,
    pub kdf: TpmiAlgKdf,
}

pub type TpmsSchemeHmac = TpmsSchemeHash;

#[repr(C)]
#[derive(Clone, Copy)]
pub union TpmuSchemeKeyedHash {
    pub hmac: TpmsSchemeHmac,
    pub exclusive_or: TpmsSchemeXor,
    pub null: TpmsEmpty,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TpmtKeyedHashScheme {
    pub scheme: TpmiAlgKeyedhashScheme,
    pub details: TpmuSchemeKeyedHash,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TpmsKeyedHashParms {
    pub scheme: TpmtKeyedHashScheme,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union TpmuSymKeyBits {
    pub aes: TpmiAesKeyBits,
    pub sm4: TpmiSm4KeyBits,
    pub camellia: TpmiCamelliaKeyBits,
    pub sym: Tpm2KeyBits,
    pub exclusive_or: TpmiAlgHash,
    pub null: TpmsEmpty,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union TpmuSymMode {
    pub aes: TpmiAlgSymMode,
    pub sm4: TpmiAlgSymMode,
    pub camellia: TpmiAlgSymMode,
    pub sym: TpmiAlgSymMode,
    pub exclusive_or: TpmsEmpty,
    pub null: TpmsEmpty,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TpmtSymDefObject {
    pub algorithm: TpmiAlgSymObject,
    pub key_bits: TpmuSymKeyBits,
    pub mode: TpmuSymMode,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TpmsSymCipherParms {
    pub sym: TpmtSymDefObject,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct TpmsSchemeHash {
    pub hash_alg: TpmiAlgHash,
}

pub type TpmsKeySchemeEcdh = TpmsSchemeHash;
pub type TpmsKeySchemeEcmqv = TpmsSchemeHash;
pub type TpmsSigSchemeRsassa = TpmsSchemeHash;
pub type TpmsSigSchemeRsapss = TpmsSchemeHash;
pub type TpmsSigSchemeEcdsa = TpmsSchemeHash;
pub type TpmsSigSchemeSm2 = TpmsSchemeHash;
pub type TpmsSigSchemeEcschnorr = TpmsSchemeHash;
pub type TpmsSigSchemeEcdaa = TpmsSchemeHash;
pub type TpmsEncSchemeOaep = TpmsSchemeHash;
pub type TpmsEncSchemeRsaes = TpmsEmpty;

#[repr(C)]
#[derive(Clone, Copy)]
pub union TpmuAsymScheme {
    pub ecdh: TpmsKeySchemeEcdh,
    pub ecmqv: TpmsKeySchemeEcmqv,
    pub rsassa: TpmsSigSchemeRsassa,
    pub rsapss: TpmsSigSchemeRsapss,
    pub ecdsa: TpmsSigSchemeEcdsa,
    pub ecdaa: TpmsSigSchemeEcdaa,
    pub sm2: TpmsSigSchemeSm2,
    pub ecschnorr: TpmsSigSchemeEcschnorr,
    pub rsaes: TpmsEncSchemeRsaes,
    pub oaep: TpmsEncSchemeOaep,
    pub any_sig: TpmsSchemeHash,
    pub null: TpmsEmpty,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TpmtRsaScheme {
    pub scheme: TpmiAlgRsaScheme,
    pub details: TpmuAsymScheme,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TpmsRsaParms {
    pub symmetric: TpmtSymDefObject,
    pub scheme: TpmtRsaScheme,
    pub key_bits: TpmiRsaKeyBits,
    pub exponent: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TpmtEccScheme {
    pub scheme: TpmiAlgEccScheme,
    pub details: TpmuAsymScheme,
}

pub type TpmsSchemeMgf1 = TpmsSchemeHash;
pub type TpmsSchemeKdf1Sp800_56a = TpmsSchemeHash;
pub type TpmsSchemeKdf2 = TpmsSchemeHash;
pub type TpmsSchemeKdf1Sp800_108 = TpmsSchemeHash;

#[repr(C)]
#[derive(Clone, Copy)]
pub union TpmuKdfScheme {
    pub mgf1: TpmsSchemeMgf1,
    pub kdf1_sp800_56a: TpmsSchemeKdf1Sp800_56a,
    pub kdf2: TpmsSchemeKdf2,
    pub kdf1_sp800_108: TpmsSchemeKdf1Sp800_108,
    pub null: TpmsEmpty,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TpmtKdfScheme {
    pub scheme: TpmiAlgKdf,
    pub details: TpmuKdfScheme,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TpmsEccParms {
    pub symmetric: TpmtSymDefObject,
    pub scheme: TpmtEccScheme,
    pub curve_id: TpmiEccCurve,
    pub kdf: TpmtKdfScheme,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TpmtAsymScheme {
    pub scheme: TpmiAlgAsymScheme,
    pub details: TpmuAsymScheme,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TpmsAsymParms {
    pub symmetric: TpmtSymDefObject,
    pub scheme: TpmtAsymScheme,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union TpmuPublicParms {
    pub keyed_hash_detail: TpmsKeyedHashParms,
    pub sym_detail: TpmsSymCipherParms,
    pub rsa_detail: TpmsRsaParms,
    pub ecc_detail: TpmsEccParms,
    pub asym_detail: TpmsAsymParms,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union TpmuPublicId {
    pub keyed_hash: Tpm2bDigest,
    pub sym: Tpm2bDigest,
    pub rsa: Tpm2bPublicKeyRsa,
    pub ecc: TpmsEccPoint,
    pub derive: TpmsDerive,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TpmtPublic {
    pub tipe: TpmiAlgPublic,
    pub name_alg: TpmiAlgHash,
    pub object_attributes: TpmaObject,
    pub auth_policy: Tpm2bDigest,
    pub parameters: TpmuPublicParms,
    pub unique: TpmuPublicId,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bPublic {
    size: u16,
    pub public_area: [u8; mem::size_of::<TpmuPublicId>()],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bTemplate {
    size: u16,
    pub buffer: [u8; mem::size_of::<TpmtPublic>()],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bPrivateVendorSpecific {
    size: u16,
    pub buffer: [u8; TPM2_PRIVATE_VENDOR_SPECIFIC_BYTES as usize],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union TPMU_SENSITIVE_COMPOSITE {
    pub rsa: Tpm2bPrivateKeyRsa,
    pub ecc: Tpm2bEccParameter,
    pub bits: Tpm2bSensitiveData,
    pub sym: Tpm2bSymKey,
    pub any: Tpm2bPrivateVendorSpecific,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TpmtSensitive {
    pub sensitive_type: TpmiAlgPublic,
    pub auth_value: Tpm2bAuth,
    pub seed_value: Tpm2bDigest,
    pub sensitive: TPMU_SENSITIVE_COMPOSITE,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bSensitive {
    size: u16,
    pub sensitive_area: [u8; mem::size_of::<TpmtSensitive>()],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct _PRIVATE {
    integrity_outer: Tpm2bDigest,
    integrity_inner: Tpm2bDigest,
    sensitive: Tpm2bSensitive,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bPrivate {
    size: u16,
    pub buffer: [u8; mem::size_of::<_PRIVATE>()],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct TpmsIdObject {
    pub integrity_hmac: Tpm2bDigest,
    pub enc_identity: Tpm2bDigest,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bIdObject {
    size: u16,
    pub credential: [u8; mem::size_of::<TpmsIdObject>()],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct TpmsNvPublic {
    pub nv_index: TpmiRhNvIndex,
    pub name_alg: TpmiAlgHash,
    pub attributes: TpmaNv,
    pub auth_policy: Tpm2bDigest,
    pub data_size: u16,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bNvPublic {
    size: u16,
    pub nv_public: [u8; mem::size_of::<TpmsNvPublic>()],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bContextSensitive {
    size: u16,
    pub buffer: [u8; TPM2_MAX_CONTEXT_SIZE as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct TpmsContextData {
    pub integrity: Tpm2bDigest,
    pub encrypted: Tpm2bContextSensitive,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bContextData {
    size: u16,
    pub buffer: [u8; mem::size_of::<TpmsContextData>()],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct TpmsCreationData {
    pub pcr_select: TpmlPcrSelection,
    pub pcr_digest: Tpm2bDigest,
    pub locality: TpmaLocality,
    pub parent_name_alg: Tpm2AlgId,
    pub parent_name: Tpm2bName,
    pub parent_qualified_name: Tpm2bName,
    pub outside_info: Tpm2bData,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bCreationData {
    size: u16,
    pub creation_data: [u8; mem::size_of::<TpmsCreationData>()],
}

pub trait Marshalable {
    fn unmarshal(buffer: &[u8]) -> Result<(Self, usize), Tpm2Rc>
    where
        Self: Sized;

    fn marshal(&self) -> Vec<u8>;
}

pub trait Tpm2bSimple {
    fn get_size(&self) -> u16;
    fn get_buffer(&self) -> &[u8];
    fn from_bytes(buffer: &[u8]) -> Result<Self, Tpm2Rc>
        where Self: Sized;
}

impl Marshalable for Tpm2bName {
    fn unmarshal(buffer: &[u8]) -> Result<(Self, usize), Tpm2Rc> {
        // split_at panics, so we make sure to avoid that condition
        if buffer.len() < std::mem::size_of::<u16>() {
            return Err(error_codes::TSS2_MU_RC_INSUFFICIENT_BUFFER);
        }

        // Split it at the sizeof(u16), ie the first two bytes
        let (int_bytes, rest) = buffer.split_at(std::mem::size_of::<u16>());
        let temp = int_bytes.try_into();
        if temp.is_err() {
            return Err(error_codes::TSS2_BASE_RC_GENERAL_FAILURE);
        }
        let be_size_bytes: [u8; 2] = temp.unwrap();
        let got_size: u16 = u16::from_be_bytes(be_size_bytes);

        // Ensure the buffer is large enough to fullfill the size indicated
        if rest.len() != got_size.into() {
            return Err(error_codes::TSS2_MU_RC_INSUFFICIENT_BUFFER);
        }

        let mut dest: Self = Self {
            size: got_size,
            name: [0; 68], // TODO how to initialize this based on size?
        };

        // Make sure the size indicated isn't too large for the types buffer
        if rest.len() > dest.name.len() {
            return Err(error_codes::TSS2_MU_RC_INSUFFICIENT_BUFFER);
        }

        let (field_data_buf, _) = rest.split_at(got_size.into());

        // panicked at 'source slice length (5) does not match destination slice length (68)',
        //dest.name.clone_from_slice(buffer_data);
        for (dst, src) in dest.name.iter_mut().zip(field_data_buf) {
            *dst = *src
        }

        Ok((dest, std::mem::size_of::<u16>() + usize::from(got_size)))
    }

    fn marshal(&self) -> Vec<u8> {
        let mut vec = Vec::new();

        let be_bytes = self.size.to_be_bytes();
        vec.extend_from_slice(&be_bytes);
        vec.extend_from_slice(&self.name);

        vec
    }
}

impl Tpm2bSimple for Tpm2bName {
    fn get_size(&self) -> u16 {
        self.size
    }

    fn get_buffer(&self) -> &[u8] {
        &self.name[0..self.get_size() as usize]
    }

    fn from_bytes(buffer: &[u8]) -> Result<Self, Tpm2Rc> {

        // Overflow check
        if buffer.len() > u16::MAX as usize {
            return Err(error_codes::TSS2_MU_RC_BAD_SIZE);
        }

        let mut dest: Self = Self {
            size: buffer.len() as u16,
            name: [0; 68], // TODO how to initialize this based on size?
        };

        for (dst, src) in dest.name.iter_mut().zip(buffer) {
            *dst = *src
        }

        Ok(dest)
    }
}

macro_rules! impl_marshalable_scalar {
    ($T:ty) => {
        impl Marshalable for $T {
            fn unmarshal(buffer: &[u8]) -> Result<(Self, usize), Tss2Rc>
            where
                Self: Sized,
            {
                if buffer.len() < std::mem::size_of::<$T>() {
                    return Err(error_codes::TSS2_MU_RC_INSUFFICIENT_BUFFER);
                }

                let (int_bytes, rest) = buffer.split_at(std::mem::size_of::<$T>());

                let r = <$T>::from_be_bytes(int_bytes.try_into().unwrap());
                Ok((r, rest.len().into()))
            }

            fn marshal(&self) -> Vec<u8> {
                let mut vec = Vec::new();

                let be_bytes = self.to_be_bytes();
                vec.extend_from_slice(&be_bytes);

                vec
            }
        }
    };
}

impl_marshalable_scalar! { u8 }
impl_marshalable_scalar! { u16 }
impl_marshalable_scalar! { u32 }
impl_marshalable_scalar! { u64 }
impl_marshalable_scalar! { i8 }
impl_marshalable_scalar! { i16 }
impl_marshalable_scalar! { i32 }
impl_marshalable_scalar! { i64 }

macro_rules! impl_marshalable_tpm2b_simple {
    ($T:ty, $F:ident) => {
        impl Tpm2bSimple for $T {
            fn get_size(&self) -> u16 {
                self.size
            }

            fn get_buffer(&self) -> &[u8] {
                &self.$F[0..self.get_size() as usize]
            }

            fn from_bytes(buffer: &[u8]) -> Result<Self, Tpm2Rc> {

                // Overflow check
                if buffer.len() > u16::MAX as usize {
                    return Err(error_codes::TSS2_MU_RC_BAD_SIZE);
                }
        
                let mut dest: Self = Self {
                    size: buffer.len() as u16,
                    $F: [0; std::mem::size_of::<$T>() - std::mem::size_of::<u16>()],
                };
        
                for (dst, src) in dest.$F.iter_mut().zip(buffer) {
                    *dst = *src
                }
        
                Ok(dest)
            }
        }

        impl Marshalable for $T {
            fn unmarshal(buffer: &[u8]) -> Result<(Self, usize), Tpm2Rc> {
                // split_at panics, so we make sure to avoid that condition
                if buffer.len() < std::mem::size_of::<u16>() {
                    return Err(error_codes::TSS2_MU_RC_INSUFFICIENT_BUFFER);
                }

                // Split it at the sizeof(u16), ie the first two bytes
                let (int_bytes, rest) = buffer.split_at(std::mem::size_of::<u16>());
                let temp = int_bytes.try_into();
                if temp.is_err() {
                    return Err(error_codes::TSS2_BASE_RC_GENERAL_FAILURE);
                }
                let be_size_bytes: [u8; 2] = temp.unwrap();
                let got_size: u16 = u16::from_be_bytes(be_size_bytes);

                // Ensure the buffer is large enough to fullfill the size indicated
                if rest.len() != got_size.into() {
                    return Err(error_codes::TSS2_MU_RC_INSUFFICIENT_BUFFER);
                }

                let mut dest: Self = Self {
                    size: got_size,
                    // TODO best way?
                    $F: [0; std::mem::size_of::<$T>() - std::mem::size_of::<u16>()],
                };

                // Make sure the size indicated isn't too large for the types buffer
                if rest.len() > dest.$F.len() {
                    return Err(error_codes::TSS2_MU_RC_INSUFFICIENT_BUFFER);
                }

                let (field_data_buf, _) = rest.split_at(got_size.into());

                // panicked at 'source slice length (5) does not match destination slice length (68)',
                //dest.name.clone_from_slice(buffer_data);
                for (dst, src) in dest.$F.iter_mut().zip(field_data_buf) {
                    *dst = *src
                }

                Ok((dest, std::mem::size_of::<u16>() + usize::from(got_size)))
            }

            fn marshal(&self) -> Vec<u8> {
                let mut vec = Vec::new();

                let be_bytes = self.size.to_be_bytes();
                vec.extend_from_slice(&be_bytes);
                vec.extend_from_slice(&self.$F);

                vec
            }
        }
    };
}

impl_marshalable_tpm2b_simple! {Tpm2bDigest, buffer }

#[cfg(test)]
mod tests {
    use crate::{Marshalable, Tpm2Rc, Tpm2bDigest, Tpm2bName, Tpm2bSimple};

    #[test]
    fn test_unmarshal_u8() {
        let n: [u8; 3] = [0x1, 0x2, 0x3];
        let res: Result<(u8, usize), Tpm2Rc> = u8::unmarshal(&n);
        assert!(res.is_ok());
        let (x, offset) = res.unwrap();
        assert_eq!(x, 1);
        assert_eq!(offset, 2);
    }

    #[test]
    fn test_unmarshal_tpm2b_name() {
        let n: [u8; 7] = [0x00, 0x05, b'h', b'e', b'l', b'l', b'o'];

        let name_result: Result<(Tpm2bName, usize), u32> = Tpm2bName::unmarshal(&n);
        assert!(name_result.is_ok());
        let (name, offset) = name_result.unwrap();
        assert_eq!(offset, n.len());
        assert_eq!(name.get_size(), 5);
        let slice = name.get_buffer();
        assert_eq!(slice, &n[2..]);

        let m: [u8; 5] = [b'h', b'e', b'l', b'l', b'o'];
        let name_result: Result<Tpm2bName, Tpm2Rc> = Tpm2bName::from_bytes(&m);
        assert!(name_result.is_ok());
        let name2 = name_result.unwrap();
        assert_eq!(name, name2);
    }

    #[test]
    fn test_unmarshal_tpm2b_digest() {
        let n: [u8; 22] = [
            0x00, 0x14, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11,
            0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
        ];

        let name_result: Result<(Tpm2bDigest, usize), u32> = Tpm2bDigest::unmarshal(&n);
        assert!(name_result.is_ok());
        let (digest, offset) = name_result.unwrap();
        assert_eq!(offset, n.len());
        assert_eq!(digest.get_size(), 20);
        let slice = digest.get_buffer();
        assert_eq!(slice, &n[2..]);
    }
}
