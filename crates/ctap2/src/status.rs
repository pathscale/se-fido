/// CTAP status codes (CTAP 2.1 section 8.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Status {
    Ok = 0x00,
    InvalidCommand = 0x01,
    InvalidParameter = 0x02,
    InvalidLength = 0x03,
    CborUnexpectedType = 0x11,
    InvalidCbor = 0x12,
    MissingParameter = 0x14,
    LimitExceeded = 0x15,
    CredentialExcluded = 0x19,
    Processing = 0x21,
    InvalidCredential = 0x22,
    UnsupportedAlgorithm = 0x26,
    OperationDenied = 0x27,
    KeyStoreFull = 0x28,
    UnsupportedOption = 0x2b,
    InvalidOption = 0x2c,
    KeepaliveCancel = 0x2d,
    NoCredentials = 0x2e,
    UserActionTimeout = 0x2f,
    NotAllowed = 0x30,
    PinNotSet = 0x35,
    RequestTooLarge = 0x39,
    UpRequired = 0x3b,
    Other = 0x7f,
}

impl Status {
    pub const ALL: [Status; 24] = [
        Status::Ok,
        Status::InvalidCommand,
        Status::InvalidParameter,
        Status::InvalidLength,
        Status::CborUnexpectedType,
        Status::InvalidCbor,
        Status::MissingParameter,
        Status::LimitExceeded,
        Status::CredentialExcluded,
        Status::Processing,
        Status::InvalidCredential,
        Status::UnsupportedAlgorithm,
        Status::OperationDenied,
        Status::KeyStoreFull,
        Status::UnsupportedOption,
        Status::InvalidOption,
        Status::KeepaliveCancel,
        Status::NoCredentials,
        Status::UserActionTimeout,
        Status::NotAllowed,
        Status::PinNotSet,
        Status::RequestTooLarge,
        Status::UpRequired,
        Status::Other,
    ];

    pub fn code(self) -> u8 {
        self as u8
    }

    pub fn from_code(c: u8) -> Option<Status> {
        Status::ALL.into_iter().find(|s| s.code() == c)
    }
}
