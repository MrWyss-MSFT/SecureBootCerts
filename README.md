# Secure Boot Certificates Script

This PowerShell script retrieves and displays information about Secure Boot certificates and related data on a Windows system. It is meant to simplify the process of checking Secure Boot status and certificate details.

## Features

- Retrieves Secure Boot certificate information (pk, kek, db, dbx).
- Reads SVN Version information.
- Displays Secure Boot status and related attributes.
- Provides firmware details including manufacturer, release date, and version.

## Usage

To run the script, in an elevated PowerShell session, execute the following command:

```powershell
.\Show-SecureBootCerts.ps1
```

## Requirements

- UEFIv2 Module
- PowerShell 7 or later

## Demo

![Demo of Show-SecureBootCerts.ps1](./doc/img/DemoScreenshot.png)

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request with your changes. Or simply open an issue to discuss what you would like to change
