function adb-logon {
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
	function elevateUAC {
		if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
			Write-Host "This script requires administrator rights. Auto elevating in 5 seconds.."
			Start-sleep 5
			Start-Process powershell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
			exit
		}
	}
		

	# If "authorized.db" file is not found, create a new one and register currently connected device to it.
	function firstSetup {
		
		New-EventLog -source adbLogon -LogName adbLogon -MessageResourceFile "C:\Program Files\adb-logon\eventlog.dll"
		$dev = ((adb.exe devices)[1] -split '\s' | Select-String -notmatch "device").tostring();
		write-output $dev > authorized.db
		write-host "Registered new device: $dev"
	}
	

	# Generate random values and send them to Android Messaging app
	function sendOTP {
		$global:sec1=get-random -min 0 -max 99999
		$global:sec2=get-random -min 0 -max 99999
		$vc="$sec1-$sec2"
		adb.exe -s $dev shell am start -a android.intent.action.SENDTO -d sms: --es sms_body "YOUR VERIFICATION CODE IS $vc" > $null
		Write-EventLog -LogName "Application" -Source "adb-logon" -EventID 104 -EntryType Information -Message "OTP sent to device."
	}


	# Enables task manager, removes utility manager debugger registry key.
	function disableSec {
		Start-Process -Name explorer.exe
		REG add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableTaskMgr /t REG_DWORD /d 0 /f
		REG delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /f
		Write-EventLog -LogName "Application" -Source "adb-logon" -EventID 113 -EntryType Information -Message "Security Disabled."
	}


	# Disables task manager, adds utility manager debugger registry key.
	function enableSec {
		Stop-Process -Name explorer.exe
		REG add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableTaskMgr /t REG_DWORD /d 1 /f
		REG add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /f
		Write-EventLog -LogName "Application" -Source "adb-logon" -EventID 112 -EntryType Information -Message "Security Enabled."
	}


	function failAuth {
		write-host "ADB-LOGON: Failed"
		Write-EventLog -LogName "Application" -Source "adb-logon" -EventID 111 -EntryType FailureAudit -Message "Authentication Failed."
		enableSec
		$mainwindow.close()
		Write-EventLog -LogName "Application" -Source "adb-logon" -EventID 114 -EntryType FailureAudit -Message "Force User logoff."
		shutdown /l	
	}
	
	
	Function succAuth {
		write-host "ADB-LOGON: Success"
		Write-EventLog -LogName "Application" -Source "adb-logon" -EventID 110 -EntryType SuccessAudit -Message "Authentication Successful."
		disableSec
		explorer.exe
		$mainwindow.close()
	}
	
	

	# Compares textbox input values to the generated values.
	function verify {
		$chkauth1 = $1authbox.text
		$chkauth2 = $2authbox.text
		if (($chkauth1 -eq $sec1) -and ($chkauth2 -eq $sec2)) {
			succAuth
		}
		else {
			failAuth
		}
	}


	# main window
	function main {
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
		$headerlabel.Text = "Please authenticate before continuing. An OTP has been sent to your device SMS app."
		$mainwindow.Controls.Add($headerlabel)

		$1authlabel = New-Object System.Windows.Forms.Label
		$1authlabel.Location = New-Object System.Drawing.Size(10,50) 
		$1authlabel.Size = New-Object System.Drawing.Size(90,20) 
		$1authlabel.Text = "Auth Code 1"
		$mainwindow.Controls.Add($1authlabel) 

		$1authbox = New-Object System.Windows.Forms.TextBox 
		$1authbox.Location = New-Object System.Drawing.Size(10,70) 
		$1authbox.Size = New-Object System.Drawing.Size(130,20) 
		
		$mainwindow.Controls.Add($1authbox) 

		$2authlabel = New-Object System.Windows.Forms.Label
		$2authlabel.Location = New-Object System.Drawing.Size(140,50) 
		$2authlabel.Size = New-Object System.Drawing.Size(90,20) 
		$2authlabel.Text = "Auth Code 2"
		$mainwindow.Controls.Add($2authlabel)
		
		$2authbox = New-Object System.Windows.Forms.TextBox 
		$2authbox.Location = New-Object System.Drawing.Size(140,70) 
		$2authbox.Size = New-Object System.Drawing.Size(130,20)
		$mainwindow.Controls.Add($2authbox)

		$resendbtn = New-Object System.Windows.Forms.Button
		$resendbtn.Location = New-Object System.Drawing.Size(110,90)
		$resendbtn.Size = New-Object System.Drawing.Size(60,25)
		$resendbtn.Text = "Resend"
		$resendbtn.add_click({
			write-host "ADB-LOGON: Resending OTP.."
			sendOTP
		})
		$mainwindow.Controls.Add($resendbtn)

		
		$cancelbtn = New-Object System.Windows.Forms.Button
		$cancelbtn.Location = New-Object System.Drawing.Size(150,120)
		$cancelbtn.Size = New-Object System.Drawing.Size(60,30)
		$cancelbtn.Text = "Exit"
		$cancelbtn.Add_Click({
			enableSec
			$mainwindow.Close()
		})
		$mainwindow.Controls.Add($cancelbtn)
		
		
		$okbtn = New-Object System.Windows.Forms.Button
		$okbtn.Location = New-Object System.Drawing.Size(75,120)
		$okbtn.Size = New-Object System.Drawing.Size(60,30)
		$okbtn.Text = "OK"
		$okbtn.add_click({
			verify
		})
		$mainwindow.Controls.Add($okbtn)

		
		$mainwindow.Add_Shown({
			$mainwindow.Activate()
		})
		$mainwindow.ShowDialog()
		Write-EventLog -LogName "Application" -Source "adb-logon" -EventID 100 -EntryType Information -Message "adb-logon started."
	}

	# init
	function init {
		elevateUAC
		if ((Test-Path authorized.db) -ne "True") {
			firstSetup
			enableSec
			sendOTP
			main
		}
		else {
			$authorizedDev = get-content authorized.db
			$dev = ((adb.exe devices)[1] -split '\s' | Select-String -notmatch "device").tostring();
			if ($dev -eq $authorizedDev) {
				
				enableSec
				sendOTP
				main
			}
			else {
				if ($dev -eq $null) {
					#write-host "ADB-LOGON: Device is not connected"
					#write-output "$(get-date -format "dd-MM-yyyy,HH:mm:ss"),$env:UserDomain\$env:UserName,Device not connected"
					Write-EventLog -LogName "Application" -Source "adb-logon" -EventID 3002 -EntryType Warning -Message "Device is not connected."
					enableSec
				}
				else {
					failAuth
					#write-host "ADB-LOGON: Logon Failed"
					#write-output "$(get-date -format "dd-MM-yyyy,HH:mm:ss"),$env:UserDomain\$env:UserName,Logon failed"
					#Write-EventLog -LogName "Application" -Source "adb-logon" -EventID 3001 -EntryType FailureAudit -Message "Authentication Failed."
					#enableSec
					#shutdown /l
					#Write-EventLog -LogName "Application" -Source "adb-logon" -EventID 3004 -EntryType Information -Message "User $env:Username is being logged off."
					#$mainwindow.Close()
				}
			}
		}
	}

	init
}