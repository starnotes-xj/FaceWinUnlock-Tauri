# pipe_sniffer.ps1 - 管道嗅探工具（需要以管理员身份运行）
# 用途：停止真实 Server EXE，伪装成 MansonWindowsUnlockRustServer 管道
#       捕获 DLL 发送的控制消息，并向 DLL 发送测试凭据
#
# 使用方法：
#   1. 以管理员身份打开 PowerShell
#   2. 运行: .\pipe_sniffer.ps1
#   3. 看到 "Waiting for DLL connection..." 后，锁定电脑 (Win+L)
#   4. 等待 DLL 连接并查看输出

Add-Type -TypeDefinition @"
using System;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Threading;

public class PipeSniffer {
    public static void RunControl() {
        Console.WriteLine("[*] 创建伪造控制管道: MansonWindowsUnlockRustServer");
        Console.WriteLine("[!] 请锁定电脑 (Win+L) 来触发 DLL 连接");
        Console.WriteLine();

        using (var pipe = new NamedPipeServerStream(
            "MansonWindowsUnlockRustServer",
            PipeDirection.InOut,
            1,
            PipeTransmissionMode.Byte,
            PipeOptions.None,
            4096, 4096
        )) {
            Console.WriteLine("[*] 等待 DLL 连接...");
            pipe.WaitForConnection();
            Console.WriteLine("[+] DLL 已连接！");

            int msgIndex = 1;
            try {
                while (pipe.IsConnected) {
                    byte[] buf = new byte[4096];
                    int n = pipe.Read(buf, 0, buf.Length);
                    if (n == 0) break;

                    string hex = BitConverter.ToString(buf, 0, n).Replace("-", " ");
                    string str = Encoding.UTF8.GetString(buf, 0, n);

                    Console.WriteLine($"[消息 {msgIndex++}] {n} 字节:");
                    Console.WriteLine($"  HEX: {hex}");
                    Console.WriteLine($"  STR: {str}");
                    Console.WriteLine();
                }
            } catch (IOException ex) {
                Console.WriteLine($"[i] 管道关闭: {ex.Message}");
            }
        }

        Console.WriteLine("[+] 控制管道所有消息已捕获。");
    }

    public static void SendFakeCredentials(string username, string pwd, string domain) {
        Console.WriteLine("[*] 连接到 DLL 解锁管道: MansonWindowsUnlockRustUnlock");

        try {
            using (var pipe = new NamedPipeClientStream(
                ".", "MansonWindowsUnlockRustUnlock",
                PipeDirection.Out, PipeOptions.None
            )) {
                pipe.Connect(10000);
                Console.WriteLine("[+] 已连接到解锁管道！");

                // 格式1: null 分隔字符串
                string nullDelimited = username + "\0" + pwd + "\0" + domain + "\0";
                byte[] data = Encoding.UTF8.GetBytes(nullDelimited);
                pipe.Write(data, 0, data.Length);
                Console.WriteLine($"[+] 已发送测试凭据 (null分隔格式):");
                Console.WriteLine($"    username={username}, pwd={pwd}, domain={domain}");
                Console.WriteLine($"    HEX: {BitConverter.ToString(data).Replace("-"," ")}");
            }
        } catch (Exception ex) {
            Console.WriteLine($"[-] 连接解锁管道失败: {ex.Message}");

            // 尝试 JSON 格式
            Console.WriteLine("[*] 尝试 JSON 格式...");
            try {
                using (var pipe = new NamedPipeClientStream(
                    ".", "MansonWindowsUnlockRustUnlock",
                    PipeDirection.Out, PipeOptions.None
                )) {
                    pipe.Connect(5000);
                    string json = "{\"user_name\":\"" + username + "\",\"user_pwd\":\"" + pwd + "\",\"domain\":\"" + domain + "\"}";
                    byte[] data = Encoding.UTF8.GetBytes(json);
                    pipe.Write(data, 0, data.Length);
                    Console.WriteLine($"[+] JSON 格式已发送: {json}");
                }
            } catch (Exception ex2) {
                Console.WriteLine($"[-] JSON 格式也失败: {ex2.Message}");
            }
        }
    }
}
"@

# 停止真实 Server EXE
Write-Host "[*] 检查 FaceWinUnlock-Server 进程..."
$serverProc = Get-Process "FaceWinUnlock-Server" -ErrorAction SilentlyContinue
if ($serverProc) {
    Write-Host "[*] 停止 FaceWinUnlock-Server (PID $($serverProc.Id))..."
    Stop-Process -Id $serverProc.Id -Force
    Start-Sleep -Milliseconds 800
    Write-Host "[+] 已停止"
} else {
    Write-Host "[i] FaceWinUnlock-Server 未在运行"
}

# 运行控制管道嗅探（在后台）
$controlJob = Start-Job -ScriptBlock {
    Add-Type -TypeDefinition $using:MyType 2>$null
    [PipeSniffer]::RunControl()
}

# 实际运行嗅探
[PipeSniffer]::RunControl()

Write-Host ""
Write-Host "[*] 是否要发送测试凭据到解锁管道？(y/n)"
$answer = Read-Host
if ($answer -eq 'y') {
    $testUser = Read-Host "请输入测试用户名 (如: .\YourName)"
    $testPwd = Read-Host "请输入测试密码"
    $testDomain = "."
    [PipeSniffer]::SendFakeCredentials($testUser, $testPwd, $testDomain)
}

Write-Host ""
Write-Host "[*] 按任意键退出..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
