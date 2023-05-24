pub const JUICEBOX_JNI_HTTP_HEADER_TYPE: &str = "xyz/juicebox/sdk/internal/Native$HttpHeader";
pub const JUICEBOX_JNI_HTTP_REQUEST_TYPE: &str = "xyz/juicebox/sdk/internal/Native$HttpRequest";
pub const JUICEBOX_JNI_REALM_TYPE: &str = "xyz/juicebox/sdk/Realm";
pub const JUICEBOX_JNI_PIN_HASHING_MODE_TYPE: &str = "xyz/juicebox/sdk/PinHashingMode";

pub const JNI_STRING_TYPE: &str = "java/lang/String";
pub const JNI_SHORT_OBJECT_TYPE: &str = "java/lang/Short";
pub const JNI_LONG_TYPE: &str = "J";
pub const JNI_BYTE_TYPE: &str = "B";
pub const JNI_SHORT_TYPE: &str = "S";
pub const JNI_VOID_TYPE: &str = "V";
pub const JNI_INTEGER_TYPE: &str = "I";

#[macro_export]
macro_rules! jni_array {
    ($x:expr) => {
        format!("[{}", $x)
    };
}

#[macro_export]
macro_rules! jni_object {
    ($x:expr) => {
        format!("L{};", $x)
    };
}

#[macro_export]
macro_rules! jni_signature {
    (($($arg:expr),*) => $ret:expr) => {{
        #[allow(unused_mut)]
        let mut args = String::new();
        $(args.push_str(&$arg);)*
        format!("({}){}", args, $ret)
    }};
}
