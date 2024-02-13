#Create new Certificate Request for SQL Server security
# Should be made into a function at some point
# Needs to be able to handle Cluster names/IP addresses

#Set location of the server
$Location = "City"
$State = "State"
$OU = "OU"
$Company = "Organization"

$IPv4Address = (Get-NetIPAddress -AddressState Preferred -AddressFamily IPv4 | Where-object IPAddress -ne "127.0.0.1" | Select-Object IPAddress -First 1 -ExpandProperty IPAddress)


#Create C:\CertificateRequest folder if one does not exist
$CertFolder = "C:\CertificateRequest"

if (!(Test-Path $CertFolder)) {
    New-Item -Path $CertFolder -Type Directory
}


#Get the FQDN, Computer Name, and IPv4 address
$FQDN = [System.Net.DNS]::GetHostByName($Null).HostName
$MachineName = $env:ComputerName

$CertName = "$FQDN"
$FriendlyName = "MSSQL Cert for Windows Server $FQDN"
$dns1 = $MachineName
$dns2 = $FQDN
$dns3 = $IPv4Address
$ipaddress = $IPv4Address


Write-Host "Creating CertificateRequest(CSR) for $CertName `r "

#Create Cert

$CSRPath = "$CertFolder\$($CertName).csr"
$INFPath = "$CertFolder\$($CertName).inf"
$Signature = '$Windows NT$' 
 
 
$INF =
@"
[Version]
Signature= "$Signature" 
 
[NewRequest]
Subject = "CN=$CertName, OU=$OU, O=$Company, L=$Location, S=$State, C=US"
FriendlyName = "$FriendlyName"
KeySpec = AT_KEYEXCHANGE
KeyLength = 2048
Exportable = TRUE
MachineKeySet = TRUE
SMIME = False
PrivateKeyArchive = FALSE
UserProtected = FALSE
UseExistingKeySet = FALSE
ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
ProviderType = 12
RequestType = PKCS10
KeyUsage = 0xa0
 
[EnhancedKeyUsageExtension]
 
OID=1.3.6.1.5.5.7.3.1

[Extensions]
2.5.29.17 = "{text}"
_continue_ = "dns=$dns1&"
_continue_ = "dns=$dns2&"
_continue_ = "dns=$dns3&"
_continue_ = "ipaddress=$ipaddress&"
"@
 
if (!(test-path $CSRPath)) {
    write-Host "Certificate Request is being generated `r "
    $INF | out-file -filepath $INFPath -force
    & certreq.exe -new $INFPath $CSRPath
}

write-output "Certificate Request has been generated"


---------------------------------------------------------------------------------------------------------------------------

#requires dbatools

$server = "servername"
$localCertPath = "C:\CertificateRequests"
$remoteCertPath = "C:\CertificateRequest\"

$adminuser = Import-Clixml C:\user.cred #stored credentials to access remote server

# Generate the CSR and download locally
$session = New-PSSession $server -Credential $adminuser
Invoke-Command -Session $session -FilePath 'C:\PowershellScripts\Certificates\Generate-CSR.ps1' #Separate script to generate CSR/INF files
Copy-Item -Path $remoteCertPath -Destination $localCertPath -FromSession $session -Recurse -Force

Disconnect-PSSession $session


#######
# Invoke-WebRequest code to get Cert
# This will need to be adjusted for any given certificate authority

$CSRFile = Get-ChildItem $localCertPath -Recurse -Filter "*$server*csr" #"C:\CertificateRequests\CertificateRequest\MSSQL_Cert_" + $server + ".csr"
$certType = "CertificateTemplate:WebServer"  #certificate type requested by this particular request
$certTypeHTML = [System.Net.WebUtility]::URLEncode($certType)
$CertPostURI = "https://CertificateServer/certsrv/certfnsh.asp"
    #$CertURI = "https://CertificateServer/certsrv/certrqxt.asp"
    #$response = Invoke-WebRequest -Uri $CertURI -SessionVariable sessCert -UseDefaultCredential


$CSRText = get-content $CSRFile
$CSRTextHTML = [System.Net.WebUtility]::URLEncode($CSRText)
$ContentType = "application/x-www-form-urlencoded"
$body = 'Mode=newreq&CertRequest=' + $CSRTextHTML + '&CertAttrib=' + $certTypeHTML
$certResponse = Invoke-WebRequest -Uri $CertPostURI -Method "POST" -ContentType $ContentType -Body $body -UseDefaultCredentials -SessionVariable $sessCert

$regexmatch = 'certnew.cer\?ReqID=\d+' #', "(certnew.cer\?ReqID=)\d+"'

$CertDownloadURI = "https://CertificateServer" + ($certResponse.Content | Select-String $regexmatch -AllMatches | ForEach-Object {$_.Matches} | ForEach-Object {$_.Groups[0].Value} ) + "&Enc=bin"

$CertFile = ($CSRFile.FullName).Replace(".csr", ".DER.cer")
Invoke-WebRequest -Uri $CertDownloadURI -SessionVariable $sessCert -UseDefaultCredentials -OutFile $CertFile


#######
# Copy file from local to remote
$session = New-PSSession $server -Credential $adminuser
Copy-Item -Path $CertFile -Destination $remoteCertPath -ToSession $session -Recurse -Force

#Import Certificate
Invoke-Command -ComputerName $server -Credential $adminuser -ScriptBlock { (gci c:\CertificateRequest -filter "*.cer") | Import-Certificate -CertStoreLocation "Cert:\LocalMachine\My"}

#Get Thumbprint
$script = {Get-ChildItem Cert:\LocalMachine\My\ | Where-Object FriendlyName -like "MSSQL*" | Select-Object Thumbprint}
$thumb = Invoke-Command -Session $session -ScriptBlock $script

#Register Certificate for SQL Instances
$sqlinstance = Find-DbaInstance -ComputerName $server -Credential $adminuser
$sqlinstance | Set-DbaNetworkCertificate -Credential $adminuser -Thumbprint ($thumb.Thumbprint).ToUpper()

    # Restart-DbaService -ComputerName $server -InstanceName $sqlinstance.InstanceName -Credential $su

$scriptRestartSQL = {Restart-Service MSSQLSERVER -Force}
Invoke-Command -Session $session -ScriptBlock $scriptRestartSQL
    

Disconnect-PSSession $session
