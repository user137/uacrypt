//! Re-runs `dstu_core`'s official-vector self-check against this exact compiled build - see
//! `dstu_core::selftest` for what this does and does not cover.

use crate::util::{guard, Failure};
use jni::objects::JClass;
use jni::JNIEnv;

#[no_mangle]
pub extern "system" fn Java_ua_dstucrypto_dstucore_Selftest_run<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
) {
    guard(&mut env, (), |_env| {
        dstu_core::selftest::run().map_err(|report| Failure::Crypto(report.to_string()))
    })
}
