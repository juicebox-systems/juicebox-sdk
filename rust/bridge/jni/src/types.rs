pub const LOAM_JNI_HTTP_HEADER_TYPE: &str = "me/loam/sdk/internal/Native$HttpHeader";
pub const LOAM_JNI_HTTP_REQUEST_TYPE: &str = "me/loam/sdk/internal/Native$HttpRequest";
pub const LOAM_JNI_REALM_TYPE: &str = "me/loam/sdk/Realm";

pub const JNI_STRING_TYPE: &str = "java/lang/String";
pub const JNI_LONG_TYPE: &str = "J";
pub const JNI_BYTE_TYPE: &str = "B";
pub const JNI_SHORT_TYPE: &str = "S";
pub const JNI_VOID_TYPE: &str = "V";

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
    ($($arg:expr),* ; $ret:expr) => {{
        let mut args = String::new();
        $(args.push_str(&$arg);)*
        format!("({}){}", args, $ret)
    }};
}
