# Cable
Simple Active Directory enumeration and exploitation tool.

This was fun to learn .NET dev, major WIP, and yes I am reinventing the wheel on this one.

## Usage
```
Cable.exe [Module]
Modules:
        enum [options] - Enumerate LDAP
        kerberoast [account] - Kerberoast a potentially supplied account, otherwise roast everything
        dclist - List Domain Controllers in the current Domain
```
### Enum Module Options
```
Usage: Cable.exe enum [Options]
Options:
        --users - Enumerate user objects
        --computers - Enumerate computer objects
        --spns - Enumerate objects with servicePrincipalName set
        --dclist - Enumerate domain controller objects
        --admins - Enumerate accounts with adminCount set to 1
        --constrained - Enumerate accounts with msDs-AllowedToDelegateTo set
        --unconstrained - Enumerate accounts with the TRUSTED_FOR_DELEGATION flag set
```

## Showcase
![image](https://github.com/user-attachments/assets/7f4c072f-4f9a-49ba-ab1a-5eceba5056df)

![image](https://github.com/user-attachments/assets/f897cc60-5abc-4018-b2f8-bbd9789242fa)
