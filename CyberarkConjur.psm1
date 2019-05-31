Function Write-Log
{
    param(
        $Message,
        $Level = "INFO"
    )
    Write-Verbose "$Level :: $Message" 
}

Function Disable-SslVerification
{
try
{

add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    
    public class IDontCarePolicy : ICertificatePolicy {
        public IDontCarePolicy() {}
        public bool CheckValidationResult(
            ServicePoint sPoint, X509Certificate cert,
            WebRequest wRequest, int certProb) {
            return true;
        }
    }
"@
    [System.Net.ServicePointManager]::CertificatePolicy = new-object IDontCarePolicy 
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

}
catch
{
# Ignore if error is thrown, an error is thrown if we Disaable-SSL twise in the same pwoershell session
}
}

Function Get-ResponseBodyFromException()
{
    param(
        $Exception
    )

    $responseBody = $null

    if ($Exception.Response -ne $null)
    {
        $result = $Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($result)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
    }

    return $responseBody;
}

Function Get-HeaderAsString()
{
    param(
        $Header
    )

    $headerAsString = ""

    if ($Header -ne $null)
    {
        foreach ($kv in $Header.GetEnumerator())
        {
            $headerAsString += "$($kv.Name)=$($kv.Value);"
        }
    }

    return $headerAsString
}

Function Send-HttpMethod()
{
    param(
        $Url, 
        $Method, 
        $Header, 
        $Body = $null,
        $LogResponse = $true,
        $Certificate = $null
    )
    Write-Log "URL: $Url"
    Write-Log "Method: $Method"
    Write-Log "Default Header: $(Get-HeaderAsString -Header $Header)"
    Write-Log "Body: $Body"
    $res = $null


    try
    {
        if ($Certificate -eq $null)
        {
            if ($body -eq $null)
            {
                $res = Invoke-RestMethod -Uri $url -Method $method -Header $header
            }
            else
            {
                $res = Invoke-RestMethod -Uri $url -Method $method -Header $header -Body $body
            }
        }
        else
        {
            if ($body -eq $null)
            {
                $res = Invoke-RestMethod -Uri $url -Method $method -Header $header -Certificate $Certificate -CertificateThumbprint $Certificate.Thumbprint
            }
            else
            {
                $res = Invoke-RestMethod -Uri $url -Method $method -Header $header -Body $body -Certificate $Certificate -CertificateThumbprint $Certificate.Thumbprint
            }
        }
    }
    catch
    {
        $exception = $_.Exception
        $responseBody = Get-ResponseBodyFromException($exception)
        Write-Log -Message "Response Body: `n $($responseBody | ConvertFrom-Json | ConvertTo-Json)" -Level "ERROR"
        throw $_
        break
    }
    
    if ($LogResponse)
    {
        Write-Log "HTTP Response: $($res | ConvertTo-Json)"
    }

    return $res
}

Function Test-MandatoryParameter
{
    param(
        $EnvironmentVariableName,
        $Value
    )

    if ([string]::IsNullOrWhiteSpace($Value))
    {
        Write-Host -ForegroundColor RED "Mandatory parameter is empty or missing: $EnvironmentVariableName"
        return $false
    }
    else
    {
        Write-Log "$EnvironmentVariableName=$Value"
    }

    return $true
}

Function Test-MandatoryParameters
{
    if (!(Test-MandatoryParameter -EnvironmentVariableName "CONJUR_ACCOUNT" -Value $ConjurAccount)) { return $false; }
    if (!(Test-MandatoryParameter -EnvironmentVariableName "CONJUR_AUTHN_LOGIN" -Value $ConjurUsername)) { return $false; }
    if (!(Test-MandatoryParameter -EnvironmentVariableName "CONJUR_AUTHN_API_KEY" -Value $ConjurPassword)) { return $false; }
    if (!(Test-MandatoryParameter -EnvironmentVariableName "CONJUR_APPLIANCE_URL" -Value $ConjurApplianceUrl)) { return $false; }
    # if (!(Test-MandatoryParameter -EnvironmentVariableName "CONJUR_CERT" -Value $ConjurCert)) { return $false; }
    return $true
}

Function Get-SessionTokenHeader
{
    param(
        $SessionToken
    )
    $base64 = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes((($SessionToken | ConvertTo-Json))))
    $header = @{"Authorization"= "Token token=`"$base64`""}
    return $header
}

Function Get-ConjurApiKey
{
    param(
        $ConjurAccount = $env:CONJUR_ACCOUNT,
        $ConjurUsername = $env:CONJUR_AUTHN_LOGIN,
        $ConjurPassword = $env:CONJUR_AUTHN_API_KEY,
        $ConjurApplianceUrl = $env:CONJUR_APPLIANCE_URL,
        $IgnoreSsl = $false
    )

    if (!(Test-MandatoryParameters)) { return }
    if (($IgnoreSsl)) { Disable-SslVerification }

    $url = "$ConjurApplianceUrl/authn/$ConjurAccount/login"
    $base64 = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $ConjurUsername, $ConjurPassword)))
    $basicAuthHeader = @{"Authorization"="Basic $base64"}

    return Send-HttpMethod -Url $url -Method GET -Header $basicAuthHeader
}

# This is required because powershell will automatically decode %2F to / to avoid that we must run this method on the uri that contains %2F
function FixUri($uri){
    $UnEscapeDotsAndSlashes = 0x2000000;
    $SimpleUserSyntax = 0x20000;

    $type = $uri.GetType();
    $fieldInfo = $type.GetField("m_Syntax", ([System.Reflection.BindingFlags]::Instance -bor [System.Reflection.BindingFlags]::NonPublic));

    $uriParser = $fieldInfo.GetValue($uri);
    $typeUriParser = $uriParser.GetType().BaseType;
    $fieldInfo = $typeUriParser.GetField("m_Flags", ([System.Reflection.BindingFlags]::Instance -bor [System.Reflection.BindingFlags]::NonPublic -bor [System.Reflection.BindingFlags]::FlattenHierarchy));
    $uriSyntaxFlags = $fieldInfo.GetValue($uriParser);

    $uriSyntaxFlags = $uriSyntaxFlags -band (-bnot $UnEscapeDotsAndSlashes);
    $uriSyntaxFlags = $uriSyntaxFlags -band (-bnot $SimpleUserSyntax);
    $fieldInfo.SetValue($uriParser, $uriSyntaxFlags);
}

Function Get-ConjurSessionToken
{
    param(
        $ConjurAccount = $env:CONJUR_ACCOUNT,
        $ConjurUsername = $env:CONJUR_AUTHN_LOGIN,
        $ConjurPassword = $env:CONJUR_AUTHN_API_KEY,
        $ConjurApplianceUrl = $env:CONJUR_APPLIANCE_URL,
        $IgnoreSsl = $false
    )

    $apiKey = Get-ConjurApiKey -ConjurAccount $ConjurAccount -ConjurUsername $ConjurUsername -ConjurPassword $ConjurPassword -ConjurApplianceUrl $ConjurApplianceUrl -IgnoreSsl $IgnoreSsl

    $ConjurUsername = [uri]::EscapeDataString($ConjurUsername)

    $url = ([uri]"$ConjurApplianceUrl/authn/$ConjurAccount/$ConjurUsername/authenticate")
    fixuri $url

    return Send-HttpMethod -Url $url -Method POST -Body $apiKey
}

<#
.SYNOPSIS

Get health of a conjur instance

.DESCRIPTION

Get health of a conjur instance

.INPUTS

None. You cannot pipe objects to Get-ConjurHealth.

.OUTPUTS

System.Collections.Hashtable. The health of the conjur instance.

.EXAMPLE

PS> Get-ConjurHealth
services                                database                                                                     ok
--------                                --------                                                                     --
@{possum=ok; ui=ok; ok=True}            @{ok=True; connect=; free_space=; re...                                    True


.LINK

https://www.conjur.org/api.html#health-get-health


#>
Function Get-ConjurHealth
{
    param(
        $ConjurAccount = $env:CONJUR_ACCOUNT,
        $ConjurUsername = $env:CONJUR_AUTHN_LOGIN,
        $ConjurPassword = $env:CONJUR_AUTHN_API_KEY,
        $ConjurApplianceUrl = $env:CONJUR_APPLIANCE_URL,
        # $ConjurCert = $env:CONJUR_CERT,
        $IgnoreSsl = $false
    )

    if (!(Test-MandatoryParameters)) { return }
    if (($IgnoreSsl)) { Disable-SslVerification }

    $url = "$ConjurApplianceUrl/health"
    return Send-HttpMethod -Url $url -Method "GET"
}

<#
.SYNOPSIS

Retrieve a secret from conjur

.DESCRIPTION

Retrieve a secret from conjur
Takes a Secret identifier

.PARAMETER SecretIdentifier
The identifier used to retrieve the secret

.INPUTS

None. You cannot pipe objects to Get-ConjurSecret.

.OUTPUTS

System.String. The secret retrieved.

.EXAMPLE

PS> Get-ConjurSecret -SecretIdentifier "path/to/secret"
AHfdkrjeb81hs6ah

.LINK

https://www.conjur.org/api.html#secrets-retrieve-a-secret-get


#>
Function Get-ConjurSecret()
{
    param(
        [Parameter(Position=0,mandatory=$true)]
        [string]$SecretIdentifier,
        $ConjurAccount = $env:CONJUR_ACCOUNT,
        $ConjurUsername = $env:CONJUR_AUTHN_LOGIN,
        $ConjurPassword = $env:CONJUR_AUTHN_API_KEY,
        $ConjurApplianceUrl = $env:CONJUR_APPLIANCE_URL,
        [Switch]
        $IgnoreSsl,
        $SecretKind = "variable"
    )

    $sessionToken = Get-ConjurSessionToken -ConjurAccount $ConjurAccount -ConjurUsername $ConjurUsername -ConjurPassword $ConjurPassword -ConjurApplianceUrl $ConjurApplianceUrl -IgnoreSsl $IgnoreSsl
    $header = Get-SessionTokenHeader -SessionToken $sessionToken
    # $SecretIdentifier = [uri]::EscapeDataString($SecretIdentifier)
    $url = "$ConjurApplianceUrl/secrets/$ConjurAccount/$SecretKind/$SecretIdentifier"
    # FixUri $url

    return Send-HttpMethod -Url $url -Method GET -Header $header
}

<#
.SYNOPSIS

Set a secret in conjur

.DESCRIPTION

Set a secret in conjur
Takes a secret identifier and secret value

.PARAMETER SecretIdentifier
The identifier used to set the secret

.PARAMETER SecretValue
The value of the secret

.INPUTS

None. You cannot pipe objects to Set-ConjurSecret.

.OUTPUTS

None.

.EXAMPLE

PS> Set-ConjurSecret -SecretIdentifier "path/to/secret" -SecretValue "newPasswordHere"


.LINK

https://www.conjur.org/api.html#secrets-add-a-secret-post


#>
Function Set-ConjurSecret
{
    param(
        [Parameter(Position=0,mandatory=$true)]
        [string]$SecretIdentifier,
        [Parameter(Position=1,mandatory=$true)]
        [string]$SecretValue,
        $ConjurAccount = $env:CONJUR_ACCOUNT,
        $ConjurUsername = $env:CONJUR_AUTHN_LOGIN,
        $ConjurPassword = $env:CONJUR_AUTHN_API_KEY,
        $ConjurApplianceUrl = $env:CONJUR_APPLIANCE_URL,
        [Switch]
        $IgnoreSsl,
        $SecretKind = "variable"
    )

    $sessionToken = Get-ConjurSessionToken -ConjurAccount $ConjurAccount -ConjurUsername $ConjurUsername -ConjurPassword $ConjurPassword -ConjurApplianceUrl $ConjurApplianceUrl -IgnoreSsl $IgnoreSsl
    $header = Get-SessionTokenHeader -SessionToken $sessionToken
    $url = "$ConjurApplianceUrl/secrets/$ConjurAccount/$SecretKind/$SecretIdentifier"

    return Send-HttpMethod -Url $url -Method POST -Header $header -Body $SecretValue
}

<#
.SYNOPSIS

Update a policy in conjur

.DESCRIPTION

Modifies an existing Conjur policy. Data may be explicitly deleted using the !delete, !revoke, and !deny statements. 
Unlike “replace” mode, no data is ever implicitly deleted.

.PARAMETER PolicyIdentifier
The identifier used to update the policy

.PARAMETER PolicyFilePath
The path to the policy that will be loaded

.INPUTS

None. You cannot pipe objects to Update-ConjurPolicy.

.OUTPUTS

None.

.EXAMPLE

PS> Update-ConjurPolicy -PolicyIdentifier "root" -PolicyFilePath ".\test-policy.yml"

created_roles                                                                                                   version
-------------                                                                                                   -------
@{dev:host:database/another-host=}                                                                                    4


.LINK

https://www.conjur.org/api.html#policies-update-a-policy-patch


#>
Function Update-ConjurPolicy
{
    param(
        [Parameter(Position=0,mandatory=$true)]
        [string]$PolicyIdentifier,
        [Parameter(Position=1,mandatory=$true)]
        [string]$PolicyFilePath,
        $ConjurAccount = $env:CONJUR_ACCOUNT,
        $ConjurUsername = $env:CONJUR_AUTHN_LOGIN,
        $ConjurPassword = $env:CONJUR_AUTHN_API_KEY,
        $ConjurApplianceUrl = $env:CONJUR_APPLIANCE_URL,
        [Switch]
        $IgnoreSsl
    )

    $sessionToken = Get-ConjurSessionToken -ConjurAccount $ConjurAccount -ConjurUsername $ConjurUsername -ConjurPassword $ConjurPassword -ConjurApplianceUrl $ConjurApplianceUrl -IgnoreSsl $IgnoreSsl
    $header = Get-SessionTokenHeader -SessionToken $sessionToken
    $url = "$ConjurApplianceUrl/policies/$ConjurAccount/policy/$PolicyIdentifier"
    $policyContent = Get-Content -Path $PolicyFilePath -Raw

    return Send-HttpMethod -Url $url -Header $header -Method PATCH -Body $policyContent
}

<#
.SYNOPSIS

List resource within an organization account

.DESCRIPTION

List resource within an organization account

.INPUTS

None. You cannot pipe objects to Get-ConjurResources.

.OUTPUTS

System.Collections.Hashtable. All the resources the user has access to

.EXAMPLE

PS> Get-ConjurResources

created_at      : 2019-05-29T16:42:56.284+00:00
id              : dev:policy:root
owner           : dev:user:admin
permissions     : {}
annotations     : {}
policy_versions : {@{version=1; created_at=2019-05-29T16:42:56.284+00:00; policy_text=---                                                                               4


.LINK

https://www.conjur.org/api.html#role-based-access-control-list-resources-get


#>
Function Get-ConjurResources
{
    param(
        $ConjurAccount = $env:CONJUR_ACCOUNT,
        $ConjurUsername = $env:CONJUR_AUTHN_LOGIN,
        $ConjurPassword = $env:CONJUR_AUTHN_API_KEY,
        $ConjurApplianceUrl = $env:CONJUR_APPLIANCE_URL,
        [Switch]
        $IgnoreSsl
    )

    $sessionToken = Get-ConjurSessionToken -ConjurAccount $ConjurAccount -ConjurUsername $ConjurUsername -ConjurPassword $ConjurPassword -ConjurApplianceUrl $ConjurApplianceUrl -IgnoreSsl $IgnoreSsl
    $header = Get-SessionTokenHeader -SessionToken $sessionToken
    $url = "$ConjurApplianceUrl/resources/$ConjurAccount"

    return Send-HttpMethod -Url $url -Header $header -Method GET
}

Export-ModuleMember -Function Get-ConjurHealth
Export-ModuleMember -Function Get-ConjurSecret
Export-ModuleMember -Function Set-ConjurSecret
Export-ModuleMember -Function Update-ConjurPolicy
Export-ModuleMember -Function Get-ConjurResources