package rustls.android.tests

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Ignore
import org.junit.runner.RunWith
import org.junit.Test

@RunWith(AndroidJUnit4::class)
class SmokeTests {
    @Test fun google() = check_site("google.com")
    @Test fun amazon() = check_site("amazon.com")
    @Test fun facebook() = check_site("facebook.com")
    @Test @Ignore("flaky. server reseet connection") fun netflix() = check_site("netflix.com")
    @Test fun ebay() = check_site("ebay.com")
    @Test fun apple() = check_site("apple.com")
    @Test fun microsoft() = check_site("microsoft.com")
    @Test(expected = java.lang.Error::class) // AlertReceived(HandshakeFailure)
    fun badssl() = check_site("badssl.com")
    @Test(expected = java.lang.Error::class) // AlertReceived(HandshakeFailure)
    fun badssl_expired() = check_site("expired.badssl.com")
    @Test(expected = java.lang.Error::class) // AlertReceived(HandshakeFailure)
    fun badssl_wrong_host() = check_site("wrong.host.badssl.com")
    @Test(expected = java.lang.Error::class) // AlertReceived(HandshakeFailure)
    fun badssl_self_signed() = check_site("self-signed.badssl.com")
    @Test(expected = java.lang.Error::class) // AlertReceived(HandshakeFailure)
    fun badssl_untrusted_root() = check_site("untrusted-root.badssl.com")
    @Test(expected = java.lang.Error::class) // AlertReceived(HandshakeFailure)
    fun badssl_revoked() = check_site("revoked.badssl.com")
    @Test(expected = java.lang.Error::class) // AlertReceived(HandshakeFailure)
    fun badssl_pinning_test() = check_site("pinning-test.badssl.com")

    external fun check_site(site: String)

    companion object {
        const val LIB_NAME = "rustls_native_certs_android_tests"
        init {
            System.loadLibrary(LIB_NAME)
        }
    }
}