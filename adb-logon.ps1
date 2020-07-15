<#
.SYNOPSIS
Physical 2FA token via ADB.

.DESCRIPTION
Adb-logon is a PoC Powershell module that turns a USB connected Android
device into a physical 2FA token via ADB. This script disables the
task manager, utility manager and kills	Windows Explorer when executed.
It DOES NOT take into account personalized startup programs however.
A randomized OTP will be generated and sent to the Android device's SMS app.
Successful authentication enables the programs as mentioned.
Failure to authenticate logs off the user.

As an additional security feature, the device identifier is recorded to a
file as a whitelisted device when running the script for the first time.

.NOTES
Author:			Donovan Choy (https://github.com/timebotdon)
Version:		R1.2
License:		BSD 3-Clause
Dependencies:	ADB platform tools & PowerShell v2+

* Requires administrative rights due to the adding/removing of registry keys.
* ADB debugging MUST be activated and authorized on the android device.
* Android device MUST be connected to USB BEFORE running this script.
* Disabling / Enabling the utility manager is done through the IEFO utilman.exe registry key.
  Depending on your use case, you may want to disable this by commenting out any REG add / delete
  commands related to this key. Windows 10 may automatically remove this key however.

.EXAMPLE
C:\PS> adb-logon

.LINK
Github: https://github.com/timebotdon/adb-logon
#>

# Auto elevates to administrator with a UAC prompt.

Function defineEventIDs {




}

Function elevateUAC {
	if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
		Write-Host "This script requires administrator rights. Auto elevating in 5 seconds.."
		Start-sleep 5
		Start-Process powershell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
	}
}

#Function SetupLogonService {
#}

Function installAdblogon {
	#Setup installation folder
	$currentPath = $(pwd).path
	$installPath = "C:\adb-logon"
	if ((Test-Path $installPath) -ne "True") {
		mkdir $installPath
		Copy-Item $currentPath\adb-logon.ps1 $installPath
		# new logsource
		#New-EventLog -source AdbLogon -LogName AdbLogon -MessageResourceFile $installPath\events.dll
		#Write-EventLog -source AdbLogon -LogName AdbLogon -EventID 105 -EntryType Information -Message "AdbLogon Installed"
	}
}


# If "authorized.db" is not found, create a new one and register currently connected device to it.
Function newDevice {
	$global:dev = ((.\adb devices)[1] -split '\s' | Select-String -notmatch "device").tostring();
	write-output $dev > authorized.db
	write-output "$(get-date -format "dd-MM-yyyy,HH:mm:ss"),$env:UserDomain\$env:UserName,$dev,105,info,New device registered" >> audit.log
	#Write-EventLog -source AdbLogon -LogName AdbLogon -EventID 105 -EntryType Information -Category None -Message "New device ID $dev was registered"
}


# Generate random values and send them to Android Messaging app
Function sendOTP {
	$global:otp=( (1..6) | ForEach-Object { Get-Random -Minimum 0 -Maximum 9 } ) -join ''
	write-host "DEBUG: Sending OTP to $dev .."
	.\adb -s $dev shell am start -a android.intent.action.SENDTO -d sms: --es sms_body "$otp" >> $null
	write-output "$(get-date -format "dd-MM-yyyy,HH:mm:ss"),$env:UserDomain\$env:UserName,$dev,104,info,OTP sent to device" >> audit.log
}


# Enables task manager, removes utility manager debugger registry key.
Function disableSec {
	Start-Process -Name explorer.exe
	REG add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableTaskMgr /t REG_DWORD /d 0 /f
	REG delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /f
	write-output "$(get-date -format "dd-MM-yyyy,HH:mm:ss"),$env:UserDomain\$env:UserName,$dev,203,audit,Security disabled" >> audit.log
}


# Disables task manager, adds utility manager debugger registry key.
Function enableSec {
	taskkill /f /im explorer.exe
	REG add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableTaskMgr /t REG_DWORD /d 1 /f
	REG add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /f
	write-output "$(get-date -format "dd-MM-yyyy,HH:mm:ss"),$env:UserDomain\$env:UserName,$dev,202,audit,Security enabled" >> audit.log
}


Function failAuth {
	write-host "DEBUG: Auth Failed"
	Write-EventLog -LogName "Application" -Source "adb-logon" -EventID 201 -EntryType FailureAudit -Message "Authentication failed."
	enableSec
	$mainwindow.close()
	Write-EventLog -LogName "Application" -Source "adb-logon" -EventID 107 -EntryType Information -Message "Forced user logoff."
	#shutdown /l
}


Function succAuth {
	write-host "DEBUG: Auth Success"
	write-output "$(get-date -format "dd-MM-yyyy,HH:mm:ss"),$env:UserDomain\$env:UserName,$dev,200,audit,Authentication successful" >> audit.log
	disableSec
	explorer.exe
	$mainwindow.close()
}


# Compares textbox input values to the generated values.
Function verify {
	$chkauth = $authbox.text
	if ($chkauth -eq $otp) {
		succAuth
		write-host DEBUG: success
	} else {
		failAuth
		write-host DEBUG: failed
	}
}


# main window
Function mainUi {
	Add-Type -AssemblyName System.Windows.Forms
	$mainwindow = New-Object Windows.Forms.Form
	$mainwindow.text = "Security Authentication"
	$mainwindow.Size = New-Object Drawing.Size (300,200)
	$mainwindow.controlbox = $false
	$mainwindow.showicon = $false
	$mainwindow.StartPosition = "CenterScreen"
	$mainwindow.formborderstyle = "FixedSingle"
	$mainwindow.Toplevel = $True


	$headerlabel = New-Object System.Windows.Forms.Label
	$headerlabel.Location = New-Object System.Drawing.Size(10,6)
	$headerlabel.Size = New-Object System.Drawing.Size(200,40)
	$headerlabel.Text = "Please authenticate with OTP. Click 'Send OTP' to proceed."


	$authlabel = New-Object System.Windows.Forms.Label
	$authlabel.Location = New-Object System.Drawing.Size(10,50)
	$authlabel.Size = New-Object System.Drawing.Size(90,20)
	$authlabel.Text = "OTP"


	$authbox = New-Object System.Windows.Forms.TextBox
	$authbox.Location = New-Object System.Drawing.Size(10,70)
	$authbox.Size = New-Object System.Drawing.Size(130,20)


	$sendbtn = New-Object System.Windows.Forms.Button
	$sendbtn.Location = New-Object System.Drawing.Size(110,90)
	$sendbtn.Size = New-Object System.Drawing.Size(60,25)
	$sendbtn.Text = "Send OTP"
	$sendbtn.Add_click({
		sendOTP
	})


	$cancelbtn = New-Object System.Windows.Forms.Button
	$cancelbtn.Location = New-Object System.Drawing.Size(150,120)
	$cancelbtn.Size = New-Object System.Drawing.Size(60,30)
	$cancelbtn.Text = "Exit"
	$cancelbtn.Add_Click({
		failAuth
		$mainwindow.close()
	})


	$okbtn = New-Object System.Windows.Forms.Button
	$okbtn.Location = New-Object System.Drawing.Size(75,120)
	$okbtn.Size = New-Object System.Drawing.Size(60,30)
	$okbtn.Text = "Login"
	$okbtn.Add_click({
		verify
	})

	$mainwindow.Controls.Add($headerlabel)
	$mainwindow.Controls.Add($authlabel)
	$mainwindow.Controls.Add($authbox)
	$mainwindow.Controls.Add($sendbtn)
	$mainwindow.Controls.Add($cancelbtn)
	$mainwindow.Controls.Add($okbtn)
	write-output "$(get-date -format "dd-MM-yyyy,HH:mm:ss"),$env:UserDomain\$env:UserName,$dev,100,info,adb-logon started" >> audit.log

	$mainwindow.Add_Shown({
		$mainwindow.Activate()
	})
	$mainwindow.ShowDialog()
	write-output "$(get-date -format "dd-MM-yyyy,HH:mm:ss"),$env:UserDomain\$env:UserName,$dev,101,info,adb-logon closed" >> audit.log
}

# init
Function init {
	elevateUAC
	# If authorized.db does not exist, create a new database and enable security
	if ((Test-Path "C:\Program Files\adb-logon\authorized.db") -ne "True") {
		#enableSec
		newDevice
		mainUi
	} else {
		# Compare current device ID to registered device ID in authorized.db
		$authorizedDev = get-content authorized.db
		$dev = ((.\adb devices)[1] -split '\s' | Select-String -notmatch "device").tostring();
		# If content matches to current device, disable security
		if ($dev -eq $authorizedDev) {
			#disableSec
		} else {
			write-output "$(get-date -format "dd-MM-yyyy,HH:mm:ss"),$env:UserDomain\$env:UserName,$dev,106,info,Unrecognized device" >> audit.log
			write-host "DEBUG: Unrecognized device. Quitting."
			#enableSec
		}
	}
}

init
