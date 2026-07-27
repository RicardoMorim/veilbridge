plugins {
    id("com.android.application")
}

android {
    namespace = "dev.veilbridge.android"
    compileSdk = 36

    defaultConfig {
        applicationId = "dev.veilbridge.android"
        minSdk = 26
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    lint {
        abortOnError = true
        warningsAsErrors = true
        // API 37 is preview-only in the SDK channel used by CI. Keep the lab on
        // stable API 36 until the next platform is generally available.
        disable += "OldTargetApi"
    }
}

dependencies {
    implementation(project(":protocol"))
}
