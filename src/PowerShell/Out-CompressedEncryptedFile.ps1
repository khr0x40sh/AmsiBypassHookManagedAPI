 <#
    .SYNOPSIS
        Out-CompressedEncryptedFile.ps1 - Compress and Encrypt a File

    .DESCRIPTION
        Script takes inputFile and will GZIP, "encrypt" (AES256, XOR, None), and base64 encode the file. If specified, will output to file instead of stdout 

    .PARAMETER inputFile
        (REQUIRED) File path of desired file for Compression and encryption

    .PARAMETER encrypt
        (DEFAULT=None) Encryption to use before using GZIP on the file. 
        -encrypt AES   Uses AES-256-CBC with user defined key
        -encrypt XOR   Users simple XOR with user defined key
        -encrypt None  Does not encrypt the file bytes

    .PARAMETER key
        (DEFAULT=Empty: Results in a generated key that will be osent in base64 format to STDOUT). Key in base64 encoded string for AES or XOR.
        To use a string, just convert to bytes and then base64 using [Convert]::ToBase64String([Text.Encoding]::ascii.GetBytes(string)), for example

    .PARAMETER outputFile
        File path to send the Compressed, encrypted, and base64 encoded file instead of STDOUT.

    .EXAMPLE
        Encrypt with AES256-CBC with key "1234", Compress, base64 encode, and send to stdout:
        PS> Out-CompressedEncryptedFile.ps1 -inputFile C:\Windows\Temp\test.txt -encrypt AES -key [Convert]::ToBase64String(([Text.Encoding]::ascii.GetBytes("1234")))

        Encrypt with XOR with key "1234", Compress, base64 encode, and send to an output file:
        PS> Out-CompressedEncryptedFile.ps1 -inputFile C:\Windows\Temp\test.txt -encrypt XOR -key [Convert]::ToBase64String(([Text.Encoding]::ascii.GetBytes("1234"))) -outputFile C:\users\public\downloads\test.txt

        Simply Compress, base64 encode, and send to STDOUT:
        PS> Out-CompressedEncryptedFile.ps1 -inputFile C:\Windows\Temp\test.txt -encrypt NONE 
    #>
Param(
    #File path of desired file for Compression and encryption
    [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 0)]
    [string] $inputFile = "",
    #Encryption to use before using GZIP on the file. Options are (AES, XOR, NONE). Default is NONE
    [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 1)]
    [string] $encrypt = "None",
    #Key in byte array format for AES or XOR. If unspecified, will be generated and printed to stdout as a base64 string.
    [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 2)]
    [string] $key="",
    #File path to send the Compressed, encrypted, and base64 encoded file instead of STDOUT
    [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 3)]
    [string] $outputFile
);

<# HELPER FUNCTIONS #>

<# XOR #> 
function XOR {
Param([byte[]]$fileBytes, [string]$key);

if ($key.Count -lt 4)
{
    #generate
    [byte[]]$keyB=[byte[]]::new(16);
    $g=[System.Security.Cryptography.RandomNumberGenerator]::Create();
    $g.GetBytes($keyB)
    #Write-Output "[+] Your base64 encoded generated key is: $key"
}
else
{
    $keyB = [Convert]::FromBase64String($key)
}

$outputBytes = [System.Collections.ArrayList]@()

for ($i=0; $i -lt $fileBytes.Count; $i++)
{
    $null = $outputBytes.Add(($fileBytes[$i] -bxor $keyB[$i % $keyB.Count]))
}

$outputBytes.ToArray(), [Convert]::ToBase64String($keyB)
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

function Aes-Encrypt($key, $bytes) {
    $aesManaged = Create-AesManagedObject $key
    $encryptor = $aesManaged.CreateEncryptor()
    $encryptedData = $encryptor.TransformFinalBlock($bytes, 0, $bytes.Length);
    [byte[]] $fullData = $aesManaged.IV + $encryptedData
    $aesManaged.Dispose()
    $fullData
}


function AES {
Param($fileBytes, $key);
if ($key.Length -lt 2)#4 is min length for base64. Not perfect, but works for now
{
    $key = Create-AesKey
    #$key
}
else
{
    $key2 = [Convert]::FromBase64String($key)
    [System.Collections.ArrayList] $keyList = new-object System.Collections.Generic.List[byte]
    $null = $keyList.AddRange($key2)
    #Check for required length for AES
    $count = $keyList.Count
    if ($count -lt 32){
        for ($i = $count; $i -lt 32; $i++)
        {
            $null = $keyList.Add($keyList[($i%$count)])
        }
    }
    else{
        if($count -gt 32)
        {
            $null = $keyList.RemoveRange(32,$keyList.Count-32)
        }
    }
    $key = [Convert]::ToBase64String($keyList.ToArray())
}
(Aes-Encrypt -key $key -bytes $fileBytes), $key
}

<#https://gist.github.com/khr0x40sh/ce365e54931e21f9d116d1bb5a4ba83c #>
function GZIP {
[CmdletBinding()]
    Param (
	[Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [byte[]] $byteArray = $(Throw("-byteArray is required"))
    )
	Process {
        Write-Verbose "Get-CompressedByteArray"
       	[System.IO.MemoryStream] $output = New-Object System.IO.MemoryStream
        $gzipStream = New-Object System.IO.Compression.GzipStream $output, ([IO.Compression.CompressionMode]::Compress)
      	$gzipStream.Write( $byteArray, 0, $byteArray.Length )
        $gzipStream.Close()
        $output.Close()
        $tmp = [Convert]::ToBase64String($output.ToArray())
        $tmp
    }
}

#check if inputFile actually exists
if (!([IO.File]::Exists($inputFile)))
{
    Write-Error -Message "[-] Input file not found. Please check path and try again!"
    return -1;
}

$encrypt = $encrypt.ToUpper();
$hold = [System.Collections.ArrayList]@()
$gzip =""
try
{
$hold.Clear()
switch($encrypt)
{
    "AES"{
        $hold = (AES -fileBytes ([io.file]::ReadAllBytes($inputFile)) -key $key)
        break
        }
    "XOR"{
        "XOR"
        $hold = XOR -fileBytes $([io.file]::ReadAllBytes($inputFile)) -key $key
        break
        }
    "NONE"{
        $hold.Add([io.file]::ReadAllBytes($inputFile))
        $hold.Add($null)
        break
        }
    default{
        Write-Error -Message "[-] Invalid encryption specified. Please check syntax and try again!"
        return -2
        break
        }
}
    $gzip = GZIP -byteArray $hold[0]
    try{
    if ($outputFile.Length -gt 1)
    {
        [io.file]::WriteAllText($outputFile,$gzip)    
    }
    else
    {
        Write-Output $gzip
    }
    }
    catch
    {
        Write-Error $_
        Write-Output $gzip
    }
    if ($hold[1] -ne $null)
    {
        Write-Host -foreground green "[+] Encoded key: $($hold[1])"
    }
}
catch [Exception] 
{ 
    Write-Error -Message "[-] Error occurred:"
    Write-Error $_
}



