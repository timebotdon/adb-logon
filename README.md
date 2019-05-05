# adb-logon ver.1
Physical 2FA token via ADB.

# Description
Adb-logon is a PoC Powershell module that turns a USB connected Android
device into a physical 2FA token via ADB. This script disables the
task manager, utility manager and kills	Windows Explorer when executed.
It DOES NOT take into account personalized startup programs however.
A randomized OTP will be generated and sent to the Android device's SMS app.
Successful authentication enables the programs as mentioned.
Failure to authenticate logs off the user.
	
As an additional security feature, the device identifier is recorded to a
file as a whitelisted device when running the script for the first time.

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

# Todo
* r1.2 - Logging / Auditing
* r1.3 - Auto-add scheduled task to import and run this module on user login
* r1.4 - Send email on authentication failure
* v2.1 - ADB over TCP
* v3.0 - Android App to receive notifications instead of messaging app
