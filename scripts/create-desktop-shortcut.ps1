param(
    [string]$DestinationDirectory = "",
    [string]$PythonwPath = ""
)

$ErrorActionPreference = "Stop"
$projectDirectory = Split-Path -Parent $PSScriptRoot
$entryPath = Join-Path $projectDirectory "desktop_launcher.pyw"
if (-not (Test-Path -LiteralPath $entryPath -PathType Leaf)) {
    throw "Desktop launcher is missing from this project."
}
if (-not $DestinationDirectory) {
    $DestinationDirectory = [Environment]::GetFolderPath("Desktop")
}
if (-not (Test-Path -LiteralPath $DestinationDirectory -PathType Container)) {
    throw "Shortcut destination does not exist."
}
if (-not $PythonwPath) {
    $PythonwPath = (Get-Command pythonw.exe -ErrorAction Stop).Source
}
$PythonwPath = (Resolve-Path -LiteralPath $PythonwPath).Path
$shortcutName = -join ([char[]]@(0x672C, 0x5730, 0x670D, 0x52A1, 0x53F0))
$shortcutPath = Join-Path $DestinationDirectory ($shortcutName + ".lnk")
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut($shortcutPath)
$expectedArguments = '"' + $entryPath + '"'
$shortcutDescription = "Start Local Service Manager and open its web page."
if ((Test-Path -LiteralPath $shortcutPath) -and
    ($shortcut.TargetPath -ine $PythonwPath -or $shortcut.Arguments -ne $expectedArguments) -and
    $shortcut.Description -ne $shortcutDescription) {
    throw "An unrelated shortcut already uses this name; it was not overwritten."
}
$shortcut.TargetPath = $PythonwPath
$shortcut.Arguments = $expectedArguments
$shortcut.WorkingDirectory = $projectDirectory
$shortcut.Description = $shortcutDescription
$shortcut.WindowStyle = 7
$shortcut.Save()
Write-Output $shortcutPath
