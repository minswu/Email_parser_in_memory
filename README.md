# E-mail Memory Parser

This tool is designed to parse e-mail data on physical memory. It identifies traces of e-mail transmission using YARA in the physical memory dump file and extracts information such as the sender and recipient of the e-mail and the e-mail subject from the data.

## Usage

To execute the tool, run the following command:


Replace `{Memory dump file path}` with the path to the physical memory dump file that you want to analyze. Specify `{Path to save execution result DB}` as the desired location to store the resulting execution database.

## Result Database

In the result DB, there are Service, Subject, Body, SentDate, Sender, Recipient, CC, BCC, and Description columns.

## Supported Email Services

A total of 14 email services are targeted:
- Proton Mail
- Tutanota
- Mail2Tor
- OnionMail
- Danwin1210
- DNMX
- I2P susimail
- Mailfence
- Naver Works Mail
- Outlook.com
- Yahoo Mail
- Kakao Mail
- Gmail
- Naver Mail
