param(
    [string]$DirectoryPath
)

$packers = @('nopacker','nimcrypt2','packer64','upx','hyperion','themida','vmprotect','enigma')

if (-Not (Test-Path -Path $DirectoryPath)) {
    Write-Host "Directory does not exist: $DirectoryPath"
    exit
}

# Loop through each file in the directory
foreach ($file in Get-ChildItem -Path $DirectoryPath) {
    foreach($packer in $packers) {
        # Display the file name
        Write-Host "Processing file: $($file.FullName)"
        $file_no_ext = [io.path]::GetFileNameWithoutExtension($file) 
        $file_out = $file_no_ext + "_out.exe"
        powershell.exe python "C:\\Users\\mixlh\\Diploma_Toolset\\automated.py" $packer $file.FullName $file_out
        powershell.exe python "C:\\Users\\mixlh\\Diploma_Toolset\\automated.py" "static" $packer $file.FullName $file_out
    }
}

