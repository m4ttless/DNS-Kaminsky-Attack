# DNS-Kaminsky-Attack

This repository contains the DNS-Kaminsky-Attack code.

The goal of this lab is to show how to exploit the DNS vulnerability found by Dan Kaminsky in 2008. This vulnerability allowed attackers poison the DNS cache and redirect users to malicious servers.

## Scenario

 [BankOfAllan.co.uk] <----------> [DNS VM| <----------> [ATTACKER]

## Configuration

To manage this laboratory and perform the attack some configurations must be followed on the DNS VM.

The VM can be downloaded [here](https://my.pcloud.com/publink/show?code=XZFyHA7ZfJaJlozTs1me2AHj5ftw6mFASab7)

As for the VM configuration, it is first necessary to configure a .json file as follows and the default gateway in order to receive the **FLAG** once the poisoning is successful.

### Default gw
`root add default gw <attacker-IP>`
### config.json
```json
localIP: <dns-IP>;
localDNSport: 53;
badguyIP: <badguy-IP>;
badguyDNSport: 55553;
secret: <thisIsTheSecret>;
```
