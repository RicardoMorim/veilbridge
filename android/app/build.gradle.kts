plugins {
    id("com.android.application")
}

android {
    namespace = "dev.veilbridge.android"
    compileSdk = 37

    defaultConfig {
        applicationId = "dev.veilbridge.android"
        minSdk = 26
        targetSdk = 37
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
    }
}

dependencies {
    implementation(project(":protocol"))
}
