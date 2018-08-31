# Last updated on Sept 1st 2016
# Module Version 1.4.0
# Michael Maher
# Sends VM OS Type and Hypervisor OS Type

function Get-OSType{
	[CmdletBinding()]
	param(
		[Parameter(Mandatory=$true, Position=0)]
		[string]
		$OS
    ) 
    If ($os -like "*Windows*"){
        return 'windows-corpit'
        Write-Verbose "$os reassigned as windows-corpit" 
        }
    ElseIf ($os -like "*Linux*"){
        return 'linux-corpit'
        Write-Verbose "$os reassigned as linux-corpit" 
        }
    ElseIf ($os -like "*CentOS*"){
        return 'linux-corpit'
        Write-Verbose "$os reassigned as linux-corpit" 
        }
    ElseIf ($os -like "*ESXi*"){
        return 'esxi-corpit'
        Write-Verbose "$os reassigned as esxi-corpit" 
        }
    Else{return 'unknown'}    
}


function Import-VMWareCmdLetsISE{
    $p = [Environment]::GetEnvironmentVariable('PSModulePath')
    $p += ';c:\Program Files (x86)\VMware\Infrastructure\vSphere PowerCLI\Modules\'
    [Environment]::SetEnvironmentVariable('PSModulePath',$p)
    Import-Module -Name VMware.VimAutomation.Core
}

function Convert-Size {            
    [cmdletbinding()]            
    param(            
        [validateset("Bytes","KB","MB","GB","TB")]            
        [string]$From,            
        [validateset("Bytes","KB","MB","GB","TB")]            
        [string]$To,            
        [Parameter(Mandatory=$true)]            
        [double]$Value,            
        [int]$Precision = 4            
    )            
    switch($From) {            
        "Bytes" {$value = $Value }            
        "KB" {$value = $Value * 1024 }            
        "MB" {$value = $Value * 1024 * 1024}            
        "GB" {$value = $Value * 1024 * 1024 * 1024}            
        "TB" {$value = $Value * 1024 * 1024 * 1024 * 1024}            
    }            
            
    switch ($To) {            
        "Bytes" {return $value}            
        "KB" {$Value = $Value/1KB}            
        "MB" {$Value = $Value/1MB}            
        "GB" {$Value = $Value/1GB}            
        "TB" {$Value = $Value/1TB}            
            
    }            
            
    return [Math]::Round($value,$Precision,[MidPointRounding]::AwayFromZero)            
            
}   

<#
.SYNOPSIS
"Fixes" custom objects created with Select-Object for use with ConvertTo-Json.

.DESCRIPTION
"Fixes" custom objects with array-valued properties created by passing a script block-based
hashtable to the Select-Object cmdlet in order to make them work properly with ConvertTo-Json.

This function is implemented as a filter, and therefore only accepts pipeline input. 

Typical invocation idioms:

# Scalar properties 
... | Select-Object @{ n=...; e={ <expr> } }, ... | Fix-SelectedObject | ConvertTo-Json

# Array-valued properties (note the use of ",", the array-construction operator): 
... | Select-Object @{ n=...; e={ , <expr> } }, ... | Fix-SelectedObject | ConvertTo-Json

Note:
 - Only fixes the top-level properties of each input object - nested properties are left untouched.
 - Input objects are fixed in place.
 - Input objects with read-only properties are not supported.
 - Prefix the expression with ", " (array constructor) to ensure that the 
   output property is always treated as an array, even when the input array 
   happens to contain a single element only.  

.NOTES
For background, see http://stackoverflow.com/a/38212718/45375

.EXAMPLE
'' | Select-Object @{ n='prop'; e={ @(1, 2) } } | Fix-SelectedObject | ConvertTo-Json
#>
filter Fix-SelectedObject {
  # Loop over all properties of the input object at hand...
  foreach ($prop in (Get-Member -InputObject $_ -Type Properties)) {
    # ... and, for array-typed properties, simply reassign the existing 
    # property value via @(...), the array subexpression operator, which makes
    # such properties behave like regular collections again.
    if (($val = $_.$($prop.Name)) -is [array]) {
      $_.$($prop.Name) = @($val)
    }
  }
  # Pass out the (potentially) modified object.
  $_
}
        

function Get-ESXiFacts{
<#
	.SYNOPSIS
		Gather Data from an ESXi Host

	.DESCRIPTION
		Gathers host and VM Data in Racks required format

	.PARAMETER Hostname
		Hostname of vCenter or ESXi Host 

	.PARAMETER Username
		Username to store for future connections to vCenter or ESXi Host 
        Don't specify if you don't want to store these credentials

	.PARAMETER Password
		Password to store for future connections to vCenter or ESXi Host 
        Don't specify if you don't want to store these credentials

	.EXAMPLE
    Logs into ESXi server, writes verbose output
		  PS C:\> Get-ESXiFacts -Hostname myesxi-server -Verbose



    .EXAMPLE
		PS C:\> Get-ESXiFacts -Hostname myesxi-server -Username Root -Password *******

        Logs into vCenter and stores the username and password (encrypted)
        This is the syntax used for Scheduled Tasks

    .EXAMPLE
        PS C:\> Get-VMHost -Location 'Site' | Get-ESXiFacts

	.NOTES
		Requires PowerCLI 5.x or higher
        Get the latest version of PowerCLI at http://vmware.com/go/powercli
        This is 6.3 and is backwards compatible https://www.vmware.com/resources/compatibility/sim/interop_matrix.php#interop&106=&2=

        If cached credentials are already stored and are incorrect delete the corresponding XML file from "$env:APPDATA\VMware\credstore\$Hostname.xml"   
#>
	[CmdletBinding()]
	param
	(
		[Parameter(
            Mandatory=$true, 
            Position=0, 
            HelpMessage = 'ESXi Hostname',
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true)]
		[Alias('Name')]
		[string]
		$Hostname,

		[Parameter(mandatory=$false, Position=1, HelpMessage = 'Username (defaults to root)')]
		[string]
		$Username = 'root',

		[Parameter(mandatory=$false, Position=2, HelpMessage = 'Password to connect to ESXi or vCenter')]
		[string]
		$Password
	)

	BEGIN {  
            
            # Initialise VMWare Providers
            & 'C:\Program Files (x86)\VMware\Infrastructure\vSphere PowerCLI\Scripts\Initialize-PowerCLIEnvironment.ps1'
            $rootpwd = 'C:\Users\admin-pstasks\.credentials\ESXi\root2.xml'


            
            If (-not (Get-Module -Name VMware.VimAutomation.Core)){
                Write-Output "VMWare module found, ensuring cmd-lets are exported"
                Import-Module -Name VMware.VimAutomation.Core} 
            Else {
                Write-Output "VMWare module does not exist setting it up now"
                Import-VMWareCmdLetsISE
                }
     

            Write-Verbose "Decrypt the password"

            If (-not(Test-Path $rootpwd)){
                $key = (2,3,56,34,254,222,1,1,2,23,42,54,33,233,1,34,2,7,6,5,35,43,6,6,6,6,6,6,31,33,60,23)
                $pass = Read-Host -AsSecureString
                $securepass = $pass |ConvertFrom-SecureString -Key $key
                $bytes = [byte[]][char[]]$securepass            

                $csp = New-Object System.Security.Cryptography.CspParameters
                $csp.KeyContainerName = "SuperSecretProcessOnMachine"
                $csp.Flags = $csp.Flags -bor [System.Security.Cryptography.CspProviderFlags]::UseMachineKeyStore
                $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider -ArgumentList 5120,$csp
                $rsa.PersistKeyInCsp = $true            

                $encrypted = $rsa.Encrypt($bytes,$true)
                $encrypted |Export-Clixml $rootpwd
            }
            
            #Write-Verbose "Checking $env:APPDATA\VMware\credstore\$Hostname.xml" 
                        


            $encrypted = Import-Clixml $rootpwd           

            $key = (2,3,56,34,254,222,1,1,2,23,42,54,33,233,1,34,2,7,6,5,35,43,6,6,6,6,6,6,31,33,60,23)            

            $csp = New-Object System.Security.Cryptography.CspParameters
            $csp.KeyContainerName = "SuperSecretProcessOnMachine"
            $csp.Flags = $csp.Flags -bor [System.Security.Cryptography.CspProviderFlags]::UseMachineKeyStore
            $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider -ArgumentList 5120,$csp
            $rsa.PersistKeyInCsp = $true            

            $token = [char[]]$rsa.Decrypt($encrypted, $true) -join "" |ConvertTo-SecureString -Key $key
            $cred = New-Object System.Management.Automation.PsCredential $Username,$token           

           
            Connect-VIServer -Server $hostname -Credential $cred

                } # End Begin
	PROCESS{
                $body = Get-VMHost -Name $hostname | Get-View | 
                    Select -first 1 @{N="date";E={[Math]::Floor([decimal](Get-Date(Get-Date).ToUniversalTime()-uformat "%s"))}}, # Unix time
                        @{N="host_cpus";E={($_.Hardware.CpuInfo.NumCpuPackages * $_.Hardware.CpuInfo.NumCpuCores)}},
                        @{N="host_disk";E={(Convert-Size -From Bytes -To MB -Value ((Get-EsxCli -VMHost $hostname).storage.filesystem.list()| Where Type -like 'VMFS*' | select -ExpandProperty size))}}, # In MB
                        @{N="host_memory";E={[string]([System.Math]::Round((Convert-Size -From Bytes -To MB -Value ($_.Hardware.MemorySize)),0))}}, # Racks expects a string not an int in MB
                        @{N="host_sn";E={(Get-EsxCli -VMHost $hostname).hardware.platform.get().SerialNumber}},
                        @{N="host_os";E={Get-OSType((Get-View –ViewType HostSystem -Property Config.Product | select {$_.Config.Product.FullName}).'$_.Config.Product.FullName')}},
                        # Unused Host Data
                        # @{N="host_hardware";E={$_.Hardware.SystemInfo.Vendor+ " " + $_.Hardware.SystemInfo.Model}},
                        # @{N="host_cpus";E={"PROC:" + $_.Hardware.CpuInfo.NumCpuPackages + " CORES:" + $_.Hardware.CpuInfo.NumCpuCores + " MHZ: " + [math]::round($_.Hardware.CpuInfo.Hz / 1000000, 0)}},
                        @{N="hostname";E={$hostname}},
                        @{N="vm_update2";E={1}},
                        @{N="vms";E={,@(Get-VM |
                            Select @{N="disk";E={Convert-Size -From KB -To MB -Value (Get-HardDisk $_.name).CapacityKB}},
                                @{N="memory";E={[string]($_.MemoryMB)}},
                                @{N="name";E={$_.Name }},
                                @{N="status";E={If($_.PowerState -eq 1){'Running'}Else{'Off'}}},
                                @{N="uuid";E={$_ | %{(Get-View $_.Id).config.uuid}}},
                                @{N="vcpu";E={[string]($_.NumCpu)}},
                                @{N="os";E={Get-RacksOS($_ | Get-View).summary.config.GuestFullName}}) # Need to change the OS value to a Racks format 
                        }},
                        @{N="all_units_megabytes";E={"true"}} | Fix-SelectedObject | ConvertTo-Json -Depth 2 
		        

                Write-Verbose "JSON body is $body"
                # For the last line see https://powershell.org/forums/topic/convertto-json-adds-count-and-value-property-names/

                Disconnect-VIServer $hostname -Force -Confirm:$false


                # Headers
                $headers = $(@{
			        #"Content-type" = "application/x-www-form-urlencoded"
			        "Content-type" = "application/json"
                    "Accept" = "text/plain"
		        })

		        # Set the URI variable for Racks
		        $uri = "https://api.company.com/public/api.php"

                # Method to use for the Rest Call
		        $method = "POST"

		        # Make the REST Call
		        try {
			        $postResult = Invoke-RestMethod -Uri $uri -Method $method -header $headers -Body $body -ErrorAction:Stop -WarningAction:Inquire -ErrorVariable RestError
                    Write-Verbose "Racks returned $postResult"
                   
                        if ($RestError){
                            $HttpStatusCode = $RestError.ErrorRecord.Exception.Response.StatusCode.value__
                            $HttpStatusDescription = $RestError.ErrorRecord.Exception.Response.StatusDescription
    
                            Throw "Http Status Code: $($HttpStatusCode) `nHttp Status Description: $($HttpStatusDescription)"
                        }
		            } 
                catch {
			        Write-Error -message "Could not reach the API"
		            }
            
            }

    End{} 
}


