import jetbrains.buildServer.configs.kotlin.*
import jetbrains.buildServer.configs.kotlin.buildFeatures.Swabra
import jetbrains.buildServer.configs.kotlin.buildFeatures.swabra
import jetbrains.buildServer.configs.kotlin.buildSteps.script
import jetbrains.buildServer.configs.kotlin.pipelines.*
import jetbrains.buildServer.configs.kotlin.triggers.vcs

/*
The settings script is an entry point for defining a TeamCity
project hierarchy. The script should contain a single call to the
project() function with a Project instance or an init function as
an argument.

VcsRoots, BuildTypes, Templates, and subprojects can be
registered inside the project using the vcsRoot(), buildType(),
template(), and subProject() methods respectively.

To debug settings scripts in command-line, run the

    mvnDebug org.jetbrains.teamcity:teamcity-configs-maven-plugin:generate

command and attach your debugger to the port 8000.

To debug in IntelliJ Idea, open the 'Maven Projects' tool window (View
-> Tool Windows -> Maven Projects), find the generate task node
(Plugins -> teamcity-configs -> teamcity-configs:generate), the
'Debug' option is available in the context menu for the task.
*/

version = "2026.2"

project {
    description = "在不支持红外摄像头，IR摄像头的设备上使用人脸识别进行解锁，替代输入PIN，更方便的使用"

    buildType(Build)
    buildType(Build1)

    pipeline(Test)
}

object Build : BuildType({
    name = "Build"

    publishArtifacts = PublishMode.SUCCESSFUL

    vcs {
        root(DslContext.settingsRoot)
    }

    triggers {
        vcs {
        }
    }
})

object Build1 : BuildType({
    name = "Build 1"

    vcs {
        root(DslContext.settingsRoot)
    }

    triggers {
        vcs {
        }
    }
})


object Test : Pipeline({
    name = "test"

    repositories {
        repository(DslContext.settingsRoot)
    }

    triggers {
        vcs {
        }
    }

    job(Test_Job1)
})

object Test_Job1 : Job({
    id("Job1")
    name = "Job 1"

    params {
        param("env.RUSTUP_HOME", """D:\Rust""")
        param("env.RUSTUP_TOOLCHAIN", "stable-x86_64-pc-windows-msvc")
        param("env.LIBCLANG_PATH", """D:\LLVM\bin""")
        param("env.PATH", """D:\OpenCV\build\x64\vc16\bin;D:\OpenCV\openvino_runtime;D:\LLVM\bin;D:\OpenCV;D:\Rust\CARGO\bin;C:\Program Files\Git\cmd;D:\nodejs;C:\Program Files\CMake\bin;C:\Java\bin;C:\Windows\System32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Windows\System32\OpenSSH""")
        param("env.CARGO_HOME", """D:\Rust\CARGO""")
    }

    steps {
        script {
            name = "检查构建环境"
            scriptContent = """
                where cargo
                where rustup
                where opencv_world4120.dll
                where libclang.dll
                set PATH
                rustup show active-toolchain
                cargo --version
                rustc --version
                node --version
                npm --version
            """.trimIndent()
        }
        script {
            name = "Rust 检查"
            scriptContent = """
                cargo fmt --all -- --check
                cargo check -p winlogon -p unlock -p launcher
            """.trimIndent()
        }
        script {
            name = "构建 Rust 运行时"
            scriptContent = "cargo build --release -p winlogon -p unlock -p launcher"
        }
        script {
            name = "Rust 测试"
            scriptContent = """
                cargo test -p winlogon
                cargo test -p unlock
            """.trimIndent()
        }
        script {
            name = "构建 UI"
            scriptContent = """
                npm ci
                npm run build
            """.trimIndent()
            param("working-directory", "UI")
        }
        script {
            name = "打包 FaceWinlock 安装程序"
            scriptContent = """
                powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File ".\build.ps1"
                if errorlevel 1 exit /b 1
            """.trimIndent()
        }
    }

    features {
        swabra {
            filesCleanup = Swabra.FilesCleanup.BEFORE_BUILD
            forceCleanCheckout = true
        }
    }

    outputFiles {
        pipelineArtifacts("target/release/bundle/nsis/*.exe")
        pipelineArtifacts("target/release/FaceWinUnlock-Server.exe")
        pipelineArtifacts("target/release/facewinunlock-tauri.exe")
        pipelineArtifacts("target/release/FaceWinUnlock_Tauri.dll")
        pipelineArtifacts("target/release/FaceWinUnlock-Passkey.msix")
        pipelineArtifacts("target/release/FaceWinUnlock-Passkey.cer")
    }
})
