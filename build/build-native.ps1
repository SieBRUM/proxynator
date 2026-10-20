<#
.SYNOPSIS
  Builds the hook DLLs of the injection capture mode (native/windows/hook) for x64 and x86.

.DESCRIPTION
  Needs CMake and Visual Studio (or the Build Tools) with the "Desktop development with C++" workload. The DLLs are
  installed into artifacts/native/win-x64 and artifacts/native/win-x86, where the .NET build picks them up
  (build/NativeHook.targets). Run it again after changing the native sources, then rebuild the .NET projects.

.EXAMPLE
  ./build/build-native.ps1
  ./build/build-native.ps1 -Configuration Debug
#>
param(
    [ValidateSet('Release', 'Debug')]
    [string] $Configuration = 'Release'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$source = Join-Path $root 'native/windows/hook'

foreach ($target in @(@{ Platform = 'x64'; Rid = 'win-x64' }, @{ Platform = 'Win32'; Rid = 'win-x86' })) {
    $build = Join-Path $root ".cache/native/$($target.Rid)"
    $install = Join-Path $root "artifacts/native/$($target.Rid)"
    cmake -S $source -B $build -A $target.Platform
    if ($LASTEXITCODE -ne 0) { throw "CMake configure failed for $($target.Rid)." }
    cmake --build $build --config $Configuration --parallel
    if ($LASTEXITCODE -ne 0) { throw "Build failed for $($target.Rid)." }
    cmake --install $build --config $Configuration --prefix $install
    if ($LASTEXITCODE -ne 0) { throw "Install failed for $($target.Rid)." }
}

Write-Host "Hook DLLs are in $(Join-Path $root 'artifacts/native')."
