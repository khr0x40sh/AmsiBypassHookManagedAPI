<#
    .SYNOPSIS
        UnCompressAnEncryptedFile.ps1 - DeCompress and decrypt a File

    .DESCRIPTION
        Script takes inputFile and will base64 decode, GunZIP, and "decrypt" (AES256, XOR, None)the file. If specified, will output to file instead of stdout 

    .PARAMETER inputFile
        (REQUIRED) File path of desired file for decompression and decryption

    .PARAMETER decrypt
        (DEFAULT=None) Decryption to use before using GZIP on the file. 
        -encrypt AES   Uses AES-256-CBC with user defined key
        -encrypt XOR   Users simple XOR with user defined key
        -encrypt None  Does not decrypt the file bytes

    .PARAMETER key
        (REQUIRED. default is $null for NONE encryption) Key in base64 encoded string for AES or XOR.

    .PARAMETER outputFile
        File path to send the decompressed, decrypted, and base64 decoded file instead of STDOUT.

    .EXAMPLE
        Base64 decode, decompress, decrypt with AES256-CBC with key "1234", and send to stdout:
        PS> Out-CompressedEncryptedFile.ps1 -inputFile C:\Windows\Temp\test.txt -decrypt AES -key [Convert]::ToBase64String(([Text.Encoding]::ascii.GetBytes("1234")))

        Base64 decode, decompress, decrypt with XOR with key "1234", and send to an output file:
        PS> Out-CompressedEncryptedFile.ps1 -inputFile C:\Windows\Temp\test.txt -decrypt XOR -key [Convert]::ToBase64String(([Text.Encoding]::ascii.GetBytes("1234"))) -outputFile C:\users\public\downloads\test.txt

        Base64 decode, decompress, and send to STDOUT:
        PS> Out-CompressedEncryptedFile.ps1 -inputFile C:\Windows\Temp\test.txt -encrypt NONE 
    #>
Param(
    #File path of desired file for Compression and encryption
    [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 0)]
    [string] $inputFile = "",
    #Encryption to use before using GZIP on the file. Options are (AES, XOR, NONE). Default is NONE
    [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 1)]
    [string] $decrypt = "AES",
    #Key in byte array format for AES or XOR. If unspecified, will be generated and printed to stdout as a base64 string.
    [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 2)]
    [string] $key="",
    #File path to send the Compressed, encrypted, and base64 encoded file instead of STDOUT
    [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 3)]
    [string] $outputFile
);

<# HELPER FUNCTIONS #>

<# XOR #> 
function XOR {
Param([byte[]]$fileBytes, [string]$key);

$keyB = [Convert]::FromBase64String($key)

$outputBytes = [System.Collections.ArrayList]@()

for ($i=0; $i -lt $fileBytes.Count; $i++)
{
    $null = $outputBytes.Add(($fileBytes[$i] -bxor $keyB[$i % $keyB.Count]))
}

$outputBytes.ToArray()
}

<# AES #>
#https://gist.github.com/khr0x40sh/585bbb2c9ef059230b2db5f0182bf009
function Create-AesManagedObject($key, $IV) {
    $aesManaged = New-Object "System.Security.Cryptography.AesManaged"
    $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aesManaged.BlockSize = 128
    $aesManaged.KeySize = 256
    if ($IV) {
        if ($IV.getType().Name -eq "String") {
            $aesManaged.IV = [System.Convert]::FromBase64String($IV)
        }
        else {
            $aesManaged.IV = $IV
        }
    }
    if ($key) {
        if ($key.getType().Name -eq "String") {
            $aesManaged.Key = [System.Convert]::FromBase64String($key)
        }
        else {
            $aesManaged.Key = $key
        }
    }
    $aesManaged
}

function Create-AesKey() {
    $aesManaged = Create-AesManagedObject
    $aesManaged.GenerateKey()
    [System.Convert]::ToBase64String($aesManaged.Key)
}

function Aes-Decrypt($key, $bytes) {
    $IV = $bytes[0..15]
    $aesManaged = Create-AesManagedObject $key $IV
    $decryptor = $aesManaged.CreateDecryptor();
    $unencryptedData = $decryptor.TransformFinalBlock($bytes, 16, $bytes.Length - 16);
    $aesManaged.Dispose()
    $unencryptedData
}


function AES {
Param($fileBytes, $key)
    $key2 = [Convert]::FromBase64String($key)
    (Aes-Decrypt -key $key -bytes $fileBytes)
}

<#https://gist.github.com/khr0x40sh/ce365e54931e21f9d116d1bb5a4ba83c #>
function GZIP {
	[CmdletBinding()]
    Param (
		[Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [byte[]] $byteArray = $(Throw("-byteArray is required"))
    )
	Process {
	    Write-Verbose "Get-DecompressedByteArray"
        $input = New-Object System.IO.MemoryStream( , $byteArray )
	    $output = New-Object System.IO.MemoryStream
        $gzipStream = New-Object System.IO.Compression.GzipStream $input, ([IO.Compression.CompressionMode]::Decompress)
	    $gzipStream.CopyTo( $output )
        $gzipStream.Close()
		$input.Close()
		[byte[]] $byteOutArray = $output.ToArray()
        $byteOutArray
    }
}

#check if inputFile actually exists
if (!([IO.File]::Exists($inputFile)))
{
    Write-Error -Message "[-] Input file not found. Please check path and try again!"
    return -1;
}

$encrypt = $decrypt.ToUpper();
$hold = @()
$gzip = GZIP ([Convert]::FromBase64String([io.file]::ReadAllText($inputFile)))
try
{
$hold.Clear()
switch($decrypt)
{
    "AES"{
        $hold = AES -fileBytes $gzip -key $key
        break
        }
    "XOR"{
        "XOR"
        $hold = XOR -fileBytes $gzip -key $key
        break
        }
    "NONE"{
        $hold = $gzip
        break
        }
    default{
        Write-Error -Message "[-] Invalid decryption specified. Please check syntax and try again!"
        return -2
        break
        }
}
    try{
    if ($outputFile.Length -gt 1)
    {
        [io.file]::WriteAllBytes($outputFile,$hold)    
    }
    else
    {
        Write-Output $hold
    }
    }
    catch
    {
        Write-Error $_
        Write-Output $hold
    }
}
catch [Exception] 
{ 
    Write-Error -Message "[-] Error occurred:"
    Write-Error $_
}



