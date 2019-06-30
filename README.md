# adb-logon r1.1
Physical 2FA token via ADB.

# Description
Adb-logon is a PoC Powershell module that adds an additional layer of Desktop security
by turning a USB connected Android device into a physical 2FA token.
This script disables the task manager, utility manager and kills
Windows Explorer when executed. It DOES NOT take into account personalized
startup programs however. A randomized OTP will be generated and sent to the
Android device's SMS app via the Android Debug Bridge. Successful authentication
enables the programs as mentioned. Failure to authenticate logs off the user.
	
As an additional security feature, the device identifier is recorded to a
file as a whitelisted device when running the script for the first time. Devices connected
to the machine that does not match the whitelisted ID is automatically kicked / forced logoff.

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
2. Import the powershell module
3. Run the module with adb-logon

## Event Logging
Information
* 100 - adb-logon started
* 101 - Device connected
* 102 - Device disconnected
* 103 - OTP generated
* 104 - OTP sent to device
* 105 - New device registered
* 106 - No devices detected
* 107 - Unrecognized device
* 108 - Security Enabled
* 109 - Security Disabled
* 110 - Force user logoff
* 111 - Alert via Email
Audit
* 200 - Authentication Successful
* 201 - Authentication Failure


# Future Features
* r1.2 - Logging / Auditing
* r1.3 - Auto-add scheduled task to import and run this module on user login
* r1.4 - Lock workstation and run script when device is unplugged.
* r1.5 - Send email on authentication failure
* r1.6 - Password logon
* r2.1 - ADB over TCP
* r3.0 - Android App to receive notifications instead of messaging app
