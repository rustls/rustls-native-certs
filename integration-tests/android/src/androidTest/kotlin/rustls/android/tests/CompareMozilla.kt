package rustls.android.tests

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.runner.RunWith
import org.junit.Test

@RunWith(AndroidJUnit4::class)
class CompareMozilla {
    @Test external fun test_does_not_have_many_roots_unknown_by_mozilla()
    @Test external fun test_contains_most_roots_known_by_mozilla()
    @Test external fun util_list_certs()

    companion object {
        const val LIB_NAME = "rustls_native_certs_android_tests"
        init {
            System.loadLibrary(LIB_NAME)
        }
    }
}