package dev.firezone.android.core

import dagger.hilt.android.testing.HiltAndroidRule
import dagger.hilt.android.testing.HiltAndroidTest
import org.junit.Rule
import org.junit.Test

@HiltAndroidTest
class SmokeTest {

    @get:Rule
    var hiltRule = HiltAndroidRule(this)

    @Test
    fun alwaysPass() {
        assert(true)
    }

    @Test
    fun alwaysFail() {
        assert(false)
    }
}