<# 
.SYNOPSIS 
	Checks user accounts in a specified OU (includes child OUs) and sends an email if the user account's password will expire with a specified interval.
.DESCRIPTION 
	Will check an OU for any accounts that have a PasswordLastSet value, is enabled, and password can expire. This script will also query active directory for the MaxPasswordAge.
	Users will receive an email notification (based on the AD "EmailAddres" property) if their password is going to expire within the specified interval by checking, the PasswordLastSet, MaxPasswordAge, and current date values. 
.NOTES 
    File Name  : PasswordExpirationNotification.ps1
    Author     : Brenton keegan - brenton.keegan@gmail.com 
    Licenced under GPLv3  
.LINK 
	https://github.com/bkeegan/PasswordExpirationNotification
    License: http://www.gnu.org/copyleft/gpl.html
.EXAMPLE 
	PasswordExpirationNotification -ou "OU=Users,DC=contoso,DC=com" -n 30 -e "admin@contoso.com" -smtp "mail.contoso.com" -from "Alerts@contoso.com" -subject "Password Expiration"
	All users in the "Users" OU (and child OUs) will receive an email if their account will expire within 30 days. A copy of any email will be set to "admin@contoso.com" and all emails will come from "Alerts@contoso.com"
#> 

#imports
import-module activedirectory


Function PasswordExpirationNotification
{
	[cmdletbinding()]
	param
		(
		
			[parameter(Mandatory=$true)]
			[alias("ou")] 
			[string]$ouToCheck,
			
			[parameter(Mandatory=$false)]
			[alias("n")] 
			[int]$notifyOn=15,
			
			[parameter(Mandatory=$false)]
			[alias("e")] 
			[string]$emailAdmin,
			
			[parameter(Mandatory=$true)]
			[alias("smtp")] 
			[string]$smtpServer,
			
			[parameter(Mandatory=$true)]
			[alias("from")] 
			[string]$emailSender,
			
			[parameter(Mandatory=$true)]
			[alias("subject")] 
			[string]$emailSubject
		)

	#emailbody
	$emailBody = "Please change your password from the <insert appropriate places to change password>. `n`nIf you have any questions or concerns about how to change your password, please feel free to contact Help Desk support: `n`n--Open a ticket at <ticket system url> or email <support email address> `n`n--Call us directly at  <support phone> `n`n--Call Extension <support extension> from any <place to call from>"

	#Queries all accounts in AD domain and stores them in username variable. only selects users with a password that expires, is enabled and has a passwordlastset value.
	$userNames = get-aduser -filter * -SearchBase $ouToCheck -properties passwordlastset,PasswordNeverExpires,emailAddress | where {$_.PasswordNeverExpires -eq $false -and $_.passwordlastset -and $_.enabled -eq $true}
	#queries the maximum password age from AD.
	$maxPasswordAge =  Get-ADDefaultDomainPasswordPolicy | Select MaxPasswordAge
	$currentDateTime = get-date

	foreach($user in $userNames)
	{
		#checks if the current date + the notification interval is a larger date than the day the password will expire (meaning, the password will expire within the interval). 
		#-and operator conditions results to exclude passwords that have already expired.
		if(($currentDateTime.AddDays($notifyOn) -ge $user.passwordlastset.AddDays($maxPasswordAge.MaxPasswordAge.Days)) -and ($currentDateTime -ge $user.passwordlastset.AddDays($maxPasswordAge.MaxPasswordAge.Days)))
		{
			$user.samaccountname
			if($user.EmailAddress)
			{
				Send-MailMessage -To $user.EmailAddress -From $emailSender -Subject $emailSubject -body $emailBody -smtpServer $smtpServer
				if($emailAdmin)
				{
					#constructions greeting and prepends it to standard body.
					$tmpEmailBody = "Hello $($user.givenname) $($user.surname), `n" + $emailBody
					Send-MailMessage -To $emailAdmin -from $emailSender -Subject $emailSubject -body $tmpEmailBody -smtpServer $smtpServer
				}
			}
			else
			{
				if($emailAdmin)
				{
					Send-MailMessage -To $emailAdmin -from $emailSender -Subject $emailSubject -body "$($user.samaccountname) is about to expire, could not notify user, no email address found" -smtpServer $smtpServer
				}
			}
		}		
	}
}
