# 通过 FaceWinUnlockPasskeyFaceAuth 管道触发一次 passkey 人脸授权请求。
# 协议：连接管道 → 写裸字节 "authorize" → 阻塞读响应（AUTHORIZED / REJECTED / TIMEOUT）。
# 服务端 request_and_wait 最长等 60s，故阻塞读必在 60s 内返回。
$ErrorActionPreference = 'Stop'
$pipe = New-Object System.IO.Pipes.NamedPipeClientStream('.', 'FaceWinUnlockPasskeyFaceAuth', [System.IO.Pipes.PipeDirection]::InOut)
try {
    $pipe.Connect(5000)
    $req = [System.Text.Encoding]::ASCII.GetBytes('authorize')
    $pipe.Write($req, 0, $req.Length)
    $pipe.Flush()
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $buf = New-Object byte[] 256
    $n = $pipe.Read($buf, 0, $buf.Length)
    $sw.Stop()
    $resp = [System.Text.Encoding]::ASCII.GetString($buf, 0, $n).Trim()
    Write-Host "RESPONSE: $resp  (elapsed $([math]::Round($sw.Elapsed.TotalSeconds,1))s)"
} finally {
    $pipe.Dispose()
}
