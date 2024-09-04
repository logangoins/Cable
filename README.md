# Cable
Simple Active Directory enumeration and exploitation tool

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
