/* OpenQPEP Official Release 1.2.8 (v1.2.8) — Android NDK JNI Bridge (arm64-v8a NEON + x86_64 AVX2) */
#include "openqpep.h"

#ifdef __ANDROID__
#include <jni.h>
JNIEXPORT jint JNICALL
Java_com_calyxlabs_nativecrypto_OpenQPEPNative_nativeAbiVersion(JNIEnv *env, jclass cls) {
    (void)env;
    (void)cls;
    return (jint)openqpep_native_abi_info();
}

JNIEXPORT void JNICALL
Java_com_calyxlabs_nativecrypto_OpenQPEPNative_nativeNtt3329(JNIEnv *env, jclass cls, jintArray coeffs) {
    (void)cls;
    if (!coeffs || (*env)->GetArrayLength(env, coeffs) != OPENQPEP_QLX_N) return;
    jint *ptr = (*env)->GetIntArrayElements(env, coeffs, NULL);
    if (!ptr) return;
    openqpep_ntt_3329((int32_t *)ptr);
    (*env)->ReleaseIntArrayElements(env, coeffs, ptr, 0);
}

JNIEXPORT void JNICALL
Java_com_calyxlabs_nativecrypto_OpenQPEPNative_nativeInvNtt3329(JNIEnv *env, jclass cls, jintArray coeffs) {
    (void)cls;
    if (!coeffs || (*env)->GetArrayLength(env, coeffs) != OPENQPEP_QLX_N) return;
    jint *ptr = (*env)->GetIntArrayElements(env, coeffs, NULL);
    if (!ptr) return;
    openqpep_inv_ntt_3329((int32_t *)ptr);
    (*env)->ReleaseIntArrayElements(env, coeffs, ptr, 0);
}

JNIEXPORT jint JNICALL
Java_com_calyxlabs_nativecrypto_OpenQPEPNative_nativeVerifyWireV5Magic(JNIEnv *env, jclass cls, jbyteArray hdr) {
    (void)cls;
    if (!hdr) return OPENQPEP_WIRE_ERR_INVALID;
    jsize n = (*env)->GetArrayLength(env, hdr);
    if (n < OPENQPEP_WIRE_V5_MAGIC_LEN) return OPENQPEP_WIRE_ERR_INVALID;
    jbyte *ptr = (*env)->GetByteArrayElements(env, hdr, NULL);
    if (!ptr) return OPENQPEP_WIRE_ERR_INVALID;
    int rc = openqpep_verify_wire_v5_magic((const uint8_t *)ptr, (size_t)n);
    (*env)->ReleaseByteArrayElements(env, hdr, ptr, JNI_ABORT);
    return (jint)rc;
}
#else
/* ISO C99 -Wpedantic non-empty translation unit marker for non-Android builds (hidden symbol). */
typedef int openqpep_jni_non_android_translation_unit_t;
#endif
