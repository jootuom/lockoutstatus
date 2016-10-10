if (!(Get-FormatData "LockoutStatusData")) {
	Update-FormatData -Append (Join-Path $PSScriptRoot `
		lockoutstatus.format.ps1xml)
}

# Formats the date into the format we want it in.
Function Format-Date {
	Param(
		$Date
	)

	if ($Date -eq $null) {
		""
	} else {
        $Date.ToString("d.M.yyyy HH:mm:ss")
    }
}

Function Format-AccountExpiration {
	Param(
		$Date
	)

	if ($Date -and ((Get-Date) -gt $Date)) {
		"True ({0})" -f ($Date.ToString("d.M.yyyy"))
	} else {
		"False"
	}
}

# Formats the expiry data so that an empty set date
# doesn't show up as " (set )"
# i.e. when a DC is unavailable.
Function Format-PWExpiration {
	Param(
		$Expired,
		$DateSet
	)

	if ($Date -eq "") {
		""
	} else {
        [string]::format("{0} (set {1})", $Expired, $DateSet)
	}
}

Function Get-LockoutStatus {
	<#
	.SYNOPSIS
	Get credential information about a user
	.DESCRIPTION
	This cmdlet displays information about the selected user:
	whether the user is locked out, when their password
	was last set and if it's expired.
	.EXAMPLE
	Get-LockoutStatus "user"
	.PARAMETER SamAccountName
	The user to get information about.
	#>
	[CmdletBinding(
		SupportsShouldProcess=$false,
		ConfirmImpact="Low"
	)]
	Param(
		[Parameter(Position=0,Mandatory=$true,ValueFromPipeline=$true)]
		$SamAccountName
	)
	begin {
		if (!(Get-Module ActiveDirectory)) {
			Import-Module ActiveDirectory
		}

		$DCs = Get-ADDomainController -Filter * |
			select -expand HostName

		$props = @{
			Properties = @(
				"AccountExpirationDate",
				"LockedOut",
				"badPwdCount",
				"AccountLockoutTime",
				"LastBadPasswordAttempt",
				"LastLogonDate",
				"PasswordExpired",
				"PasswordLastSet"
			)
		}
	}
	process {
		$results = @()

		foreach ($DC in $DCs) {
			try {
				$user = Get-ADUser -Identity $SamAccountName -Server $DC @props
			}
			catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
				"User not found on $DC."
				continue
			}
			catch [Microsoft.ActiveDirectory.Management.ADServerDownException] {
				"Unable to connect to $DC."
				continue
			}
			catch {
				Write-Debug "Unknown error: $($_.Exception.GetType().FullName)"
				throw $_
			}

			$result = New-Object PSObject -Property @{
				User = $user.SamAccountName;
				Name = $user.Name;
				Disabled = !$user.Enabled;
				Expired = Format-AccountExpiration $user.AccountExpirationDate;

				DomainController = $DC.split(".")[0];
				Locked = $user.LockedOut;
				Count = $user.badPwdCount;
				LastLock = Format-Date $user.AccountLockoutTime;
				LastBadAttempt = Format-Date $user.LastBadPasswordAttempt;
				LastLogonDate = Format-Date $user.LastLogonDate;
				PwdExpired = Format-PWExpiration $user.PasswordExpired `
					(Format-Date $user.PasswordLastSet)
			}

			$result.PSTypeNames.Insert(0, "LockoutStatusData")

			$results += $result
		}

		$results
	}
	end {

	}
}

Export-ModuleMember Get-LockoutStatus
