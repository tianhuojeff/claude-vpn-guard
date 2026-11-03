plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.tianhuo.vpnguard"
    compileSdk = 36
    defaultConfig {
        applicationId = "com.tianhuo.vpnguard"
        minSdk = 30
        targetSdk = 36
        versionCode = 3
        versionName = "0.3.0"
    }
    buildFeatures { aidl = true; buildConfig = true }
    buildTypes {
        release { isMinifyEnabled = false; signingConfig = signingConfigs.getByName("debug") }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin { jvmToolchain(17) }

dependencies {
    implementation("dev.rikka.shizuku:api:13.1.5")
    implementation("dev.rikka.shizuku:provider:13.1.5")
    implementation("org.snakeyaml:snakeyaml-engine:2.9")
}
