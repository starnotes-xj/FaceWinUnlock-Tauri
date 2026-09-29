import jetbrains.buildServer.configs.kotlin.*
import jetbrains.buildServer.configs.kotlin.buildSteps.script

version = "2025.11"

project {
    buildType(FaceWinUnlockBuild)
}

object FaceWinUnlockBuild : BuildType({
    id("Facewinlock_FaceWinUnlockBuild")
    name = "FaceWinUnlock - Windows Build"
    description = "Builds the Rust runtime, Passkey MSIX, Tauri UI and NSIS installer."

    // Use the same VCS root that stores this Kotlin DSL configuration.
    // Configure GitHub credentials in TeamCity; no token is stored in this file.
    vcs {
        root(DslContext.settingsRoot)
    }

    params {
        param("env.RUSTUP_HOME", "D:\\Rust")
        param("env.CARGO_HOME", "D:\\Rust\\CARGO")
        param("env.RUSTUP_TOOLCHAIN", "stable-x86_64-pc-windows-msvc")
    }

    requirements {
        equals("teamcity.agent.jvm.os.name", "Windows")
    }

    steps {
        script {
            id = "BuildFaceWinUnlock"
            name = "Build FaceWinUnlock"
            scriptContent = """
                powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%teamcity.build.checkoutDir%\\build.ps1"
                if errorlevel 1 exit /b 1
            """.trimIndent()
        }
    }

    artifactRules = """
        +:target/release/FaceWinUnlock_Tauri.dll
        +:target/release/FaceWinUnlock-Server.exe
        +:target/release/FaceWinUnlock-Launcher.exe
        +:target/release/FaceWinUnlock-Passkey.msix
        +:target/release/FaceWinUnlock-Passkey.cer
        +:target/release/bundle/nsis/*.exe
    """.trimIndent()
})
