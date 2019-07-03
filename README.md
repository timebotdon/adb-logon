# adb-logon r1.1
Physical 2FA token via ADB.

# Description
Adb-logon is a Powershell script that adds an additional layer of Desktop security
by turning a USB connected Android device into a physical 2FA token.
This script disables the task manager, utility manager and kills
Windows Explorer when executed. It DOES NOT take into account personalized
startup programs however. A randomized OTP will be generated and sent to the
Android device's SMS app via the Android Debug Bridge. Successful authentication
enables the programs as mentioned. Failure to authenticate logs off the user.
	
As an additional security feature, the device identifier is recorded to a
file as a whitelisted device when running the script for the first time.
Users connecting to the machine with an an device that does not match the
whitelisted ID is automatically logged off.

# Requirements
* Requires administrative rights due to the adding/removing of registry keys.
* ADB debugging MUST be activated and authorized on the android device.
* Android device MUST be connected to USB BEFORE running this script.
* Disabling / Enabling the utility manager is done through the IEFO utilman.exe registry key.
	Depending on your use case, you may want to disable this by commenting out any REG add / delete
	commands related to this key. Windows 10 may automatically remove this key however.

# Software dependencies
* ADB platform tools (included)
* PowerShell v2+

# Usage
0. Connect your ADB enabled Android device via USB
1. Start powershell with execution policy bypass from the directory containing adb-logon.ps1.
2. Run script with .\adb-logon

## Event Logging

Information
* 100 - adb-logon started
* 101 - adb-logon closed
* 102 - Device connected
* 103 - Device disconnected
* 104 - OTP sent to device
* 105 - New device registered
* 106 - Unrecognized device
* 107 - Forced user logoff
* 108 - Alert via Email

Audit
* 200 - Authentication successful
* 201 - Authentication failed
* 202 - Security enabled
* 203 - Security disabled

# Future Features
* r1.3 - Auto-add scheduled task to run this script on user login
* r1.4 - Lock workstation and run script when device is unplugged.
* r1.5 - Send an email alert on authentication failure
* r1.6 - Password logon
* r1.7 - ADB over TCP
* r2.0 - Android App to receive notifications instead of messaging app
