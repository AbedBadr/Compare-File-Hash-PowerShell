<#
.SYNOPSIS
Verifies the integrity of a file by comparing its hash to a known hash value.

.DESCRIPTION
This script calculates the hash of a specified file using a selected hashing algorithm. It then compares the computed hash against a provided hash and returns whether they match.

.PARAMETER FilePath
The path to the file to verify.

.PARAMETER ExpectedHash
The known hash to compare the computed hash against.

.PARAMETER Algorithm
The hashing algorithm to use: SHA1, SHA256, SHA512, or MD5. Default is SHA256.

.EXAMPLE
PS> .\CompareFileHash.ps1 -FilePath C:\Users\user1\Downloads\linuxmint-22-64bit.iso -ExpectedHash 123ABC123ABC123ABC123ABC

.EXAMPLE
PS> .\CompareFileHash.ps1 -FilePath C:\Users\user1\Downloads\archlinux-2025-x86_64.iso -ExpectedHash abc123abc123abc123abc123 -Algorithm SHA512
#>

param(
    [Parameter(Mandatory)] [string] $FilePath, 
    [Parameter(Mandatory)] [string] $ExpectedHash, 
    [ValidateSet("SHA1", "SHA256", "SHA512", "MD5")] [string] $Algorithm = "SHA256"
)

$ComputedHash = Get-FileHash $FilePath -Algorithm $Algorithm

if ( $ComputedHash.Hash -ieq $ExpectedHash) {
	Write-Host "SUCCESS: Hashes match." -ForegroundColor Green
    Write-Host "Computed hash: $($ComputedHash.Hash)"
    Write-Host "Expected hash: $ExpectedHash"
} else {
	Write-Host "FAILURE: Hash mismatch." -ForegroundColor Red
    Write-Host "Computed hash: $($ComputedHash.Hash)"
    Write-Host "Expected hash: $ExpectedHash"
}
