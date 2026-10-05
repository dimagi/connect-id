class ErrorCodes:
    INVALID_MESSAGE_CONTENT = "INVALID_MESSAGE_CONTENT"
    CHANNEL_DOES_NOT_EXIST = "CHANNEL_DOES_NOT_EXIST"
    NO_USER_CONSENT = "NO_USER_CONSENT"
    MESSAGE_ID_ALREADY_EXISTS = "MESSAGE_ID_ALREADY_EXISTS"

    # create_message
    RICH_MESSAGING_DISABLED = "RICH_MESSAGING_DISABLED"
    REQUEST_TOO_LARGE = "REQUEST_TOO_LARGE"
    INVALID_MESSAGE = "INVALID_MESSAGE"
    UNSUPPORTED_VERSION = "UNSUPPORTED_VERSION"
    CONTENT_LEGACY_MSG_REQUIRED = "CONTENT_LEGACY_MSG_REQUIRED"
    TOO_MANY_ATTACHMENTS = "TOO_MANY_ATTACHMENTS"
    DUPLICATE_ATTACHMENT_NAME = "DUPLICATE_ATTACHMENT_NAME"
    ATTACHMENT_PARTS_MISMATCH = "ATTACHMENT_PARTS_MISMATCH"
    ATTACHMENT_SIZE_MISMATCH = "ATTACHMENT_SIZE_MISMATCH"
    ATTACHMENT_TOO_LARGE = "ATTACHMENT_TOO_LARGE"
    MESSAGE_TOO_LARGE = "MESSAGE_TOO_LARGE"
    INVALID_EXPIRY = "INVALID_EXPIRY"
    MESSAGE_EXPIRED = "MESSAGE_EXPIRED"


# The newest message format version this server supports. Each message synced to the device
# carries the lowest version that can represent it; today that is this version for every message.
MESSAGING_VERSION = 2
# Callers may declare the version they were written for; one newer than MESSAGING_VERSION is refused
MESSAGING_VERSION_HEADER = "X-Messaging-Version"
# The format a message with attachments gets when the caller names none
DEFAULT_ATTACHMENT_FORMAT = "attachment"

# Attachments. Sizes count encrypted bytes, which are 28 bytes more than the file they hold.
MAX_ATTACHMENTS_PER_MESSAGE = 10
MAX_ATTACHMENT_BYTES = 2_621_440  # 2.5 MiB
MAX_MESSAGE_ATTACHMENT_BYTES = 15 * 1024 * 1024
# Room for the JSON part and multipart framing on top of the attachment bytes
MAX_RICH_REQUEST_OVERHEAD_BYTES = 1024 * 1024
