#------------------------------------------------------------
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#------------------------------------------------------------
param (
[string]$DnsRoot
)
Import-Module ActiveDirectory

Function OutputIdentity() {
    $FQDN = [System.Net.Dns]::GetHostByName(($env:COMPUTERNAME)).HostName
    $UserInfo = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    Write-Output "diagnose_ad 1.0"
    Write-Output ""
    Write-Output "Local Time: $(Get-Date)"
    Write-Output "  UTC Time: $($(Get-Date).toUniversalTime())"
    Write-Output ""
    Write-Output "I am $($UserInfo) running on $($env:COMPUTERNAME) ($($FQDN))"
    Write-Output ""
    $wos = Get-WmiObject -class Win32_OperatingSystem
    $os = $wos.Caption.Trim()
    if ($wos.CSDVersion -ne $Null) {
        $os = "$os - $($wos.CSDVersion)"
    }
    Write-Output "OS: $os"
    Write-Output ""
}

Function GetMembers($Group) {
  
}

# Return the domain Dn from the User or Group Dn
Function ShortenDn($Dn) {
    $pos = $Dn.IndexOf(",DC=")
    if ($pos -le 0) {
        return $Dn
    }
    return $Dn.Substring($pos+1)
}

Function GetEntities($DnsRoot) {
    Write-Output "Scanning $DnsRoot"

    $Searcher = New-Object DirectoryServices.DirectorySearcher
    $Searcher.SearchRoot = "LDAP://$($DnsRoot)"
    $Searcher.Filter = '(|(&(objectClass=group)(groupType:1.2.840.113556.1.4.803:=2147483648))(&(objectClass=user)(objectCategory=person)))'
    $Searcher.PageSize = 1000
    $b = $Searcher.PropertiesToLoad.Add("SAMAccountName")
    $b = $Searcher.PropertiesToLoad.Add("primaryGroupId")
    $b = $Searcher.PropertiesToLoad.Add("objectSid;binary")
    $b = $Searcher.PropertiesToLoad.Add("userAccountControl")
    $users = 0
    $groups = 0
    $UsersSeen = @{}
    $GroupsSeen = @{}
    $FSPSeen = @{}
    $FSPDomainsSeen = @{}
    $disabledGroups = 0
    $FSP = 0

    # Walk all entities in the AD and save their names
    $Results = $Searcher.FindAll()
    foreach($Result in $Results) {
        $attrs = $Result.Properties
        
        $udn = $attrs.Item("distinguishedName")
        if ($udn -ne $null) {
            $udn = $udn[0]
        }
        
        # Is this a user ?
        if ($attrs.Contains("primaryGroupId")) {
            # Have we seen this user before ?
            if (!$UsersSeen.Contains($udn)) {
                $UsersSeen.Set_Item($udn, @{})
                $UsersSeen.Get_Item($udn).Add('sam', $attrs.Item("SAMAccountName")[0])
                $objectSid = $attrs.Item("objectSid")
                if ($objectSid -ne $null) {
                    $sid = New-Object System.Security.Principal.SecurityIdentifier($objectSid[0])
                    $sid = $sid.Value
                    $UsersSeen.Get_Item($udn).Add('sid', $sid)
                }                
                $uac = $attrs.Item("userAccountControl")
                if ($uac -ne $Null) {
                    $uac = $uac[0]
                    $UsersSeen.Get_Item($udn).Add('uac', $uac)
                    # Check if the user is disabled
                    if ($uac -band 2) {
                        $UsersSeen.Get_Item($udn).Add('disabled', $true)
                    } else {
                        $UsersSeen.Get_Item($udn).Add('disabled', $false)
                    }
                } else {
                    $UsersSeen[$udn].Add('uac', $uac)
                    $UsersSeen[$udn].Add('disabled', $false)
                }
            }
            continue;
        }
        
        # Have we seen this group before ?
        if (!$GroupsSeen.Contains($udn)) {
            $GroupsSeen[$udn] = $attrs.Item("SAMAccountName")
            $GroupsSeen.Set_Item($udn, @{})
            $GroupsSeen.Get_Item($udn).Add('sam', $attrs.Item("SAMAccountName")[0])
            $uac = $attrs.Item("userAccountControl")
            if ($uac -ne $Null) {
                $uac = $uac[0]
                $GroupsSeen.Get_Item($udn).Add('uac', $uac)
                # Check if the group is disabled
                if ($uac -band 2) {
                    $GroupsSeen.Get_Item($udn).Add('disabled', $true)
                } else {
                    $GroupsSeen.Get_Item($udn).Add('disabled', $false)
                }
            } else {
                $GroupsSeen.Get_Item($udn).Add('uac', $uac)
                $GroupsSeen.Get_Item($udn).Add('disabled', $false)
            }

        }
    }
    $Results.Dispose()
    $Searcher.Dispose()

    $users = $UsersSeen.Count
    $groups = $GroupsSeen.Count
    $entities = $users+$groups
    $memberships = $entities

    # Walk the groups and resolve their memberships where possible
    foreach($GroupDn in $GroupsSeen.Keys) {
        if ($GroupsSeen.Item($GroupDn).Item('disabled')) {
            $disabledGroups++
            continue
        }
        $sam = $GroupsSeen.Item($GroupDn).Item('sam')
        $memberPage = 1000
        $startNum = 0
        $membersCount = 0
        $unknownUsers = 0
        
        do {
            $endNum = $startNum + $memberPage - 1
            $rangeAttr = "member;range=$startNum-$endNum"
            
            $Searcher = New-Object DirectoryServices.DirectorySearcher
            try {
                $Searcher.SearchRoot = "LDAP://$($DnsRoot)"
                #$Searcher.Filter = '(|(&(objectClass=group)(groupType:1.2.840.113556.1.4.803:=2147483648))(&(objectClass=user)(objectCategory=person)))'
                $Searcher.Filter = "(samaccountname=$sam)"
                $Searcher.CacheResults = $False
                $Searcher.PageSize = 1000
                $b = $Searcher.PropertiesToLoad.Add($rangeAttr)
                $Result = $Searcher.FindOne()
                $memberProp = $Null
                foreach($propName in $Result.Properties.PropertyNames) {
                    if (!$propName.StartsWith("member")) {
                        continue
                    }
                    $memberProp = $propName
                    break
                }
                
                # Break if we can't find any members property
                if ($memberProp -eq $Null) {
                    break
                }
                
                # Fetch our members
                $members = $Result.Properties.Item($memberProp)
                
                # Break if members are null
                if ($members -eq $Null) {
                    break
                }
                
                $lastMembers = $false
                foreach($member in $members) {
                    $p = $member.IndexOf(",CN=ForeignSecurityPrincipals,")
                    if ($p -le 0) {
                        $dn = ShortenDn $member
                        if ($domainDn -eq $dn) {
                            if (!$UserSeen.Contains($member)) {
                                # User is in our domain and doesn't exist so skip it
                                $unknownUsers++
                                continue
                            }                        
                        }
                        # User exists in our domain, or comes from a child domain
                        $membersCount++
                        continue;
                    }
                    # User is a Foreign Security Principal
                    $membersCount++   # Assume the FSP would be fed to GSA
                    
                    # Get SID info from the FSP
                    $sid = $member.Substring(3, $p-3)
                    $domainsid = $sid.Substring(0, $sid.LastIndexOf("-"))
                    
                    # Not all FSP's belong to foreign domains, some can be system SID's
                    if (!$domainsid.StartsWith("S-1-5-21-")) {
                        continue;
                    }
                    
                    if ($FSPSeen.Contains($member)) {
                        continue;
                    }
                    $FSPSeen[$member] = 1
                    $FSPDomainsSeen[$domainsid] = 1
                }
            } finally {
                $Searcher.Dispose()
            }
            

            $lastMembers = $memberProp.EndsWith("*")
            
            if (!$lastMembers) {
                $startNum += $memberPage
            }
            #Write-Output "Group was too large so crawling further"
        } while (!$lastMembers)
        $memberships += $membersCount
    }
    
    $fsps = $FSPSeen.Count
    $fspsdomains = $FSPDomainsSeen.Count
    # Adjust for Everyone + Authenticated Users + Interactive
    $groups += 3
    # Adjust for Authenticated Users + Interactive
    $memberships += 2
    # Update entities
    $entities = $users+$groups
    
    Write-Output "Unique Entities: $entities"
    Write-Output "Unique Memberships: $memberships"
    Write-Output "Unique Groups: $groups"
    Write-Output "Unique Users: $users"
    Write-Output "Unique FSP's: $fsps"
    Write-Output "Unique FSP Domains: $fspsdomains"
    Write-Output "Disabled Groups: $disabledGroups"
    Write-Output "Unknown Users: $unknownUsers"
}

if ([string]::IsNullOrEmpty($DnsRoot)) {
    $DnsRoot = (Get-ADDomain).DnsRoot
}
OutputIdentity
GetEntities($DnsRoot);
