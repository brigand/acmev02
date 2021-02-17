use base64::{encode_config, URL_SAFE_NO_PAD};

/// base64 Encoding with URL and Filename Safe Alphabet.
pub(crate) fn b64<T: AsRef<[u8]>>(data: T) -> String {
    encode_config(data, URL_SAFE_NO_PAD)
}
