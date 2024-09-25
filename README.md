# Cable
Simple Active Directory enumeration and exploitation tool.

## Usage
```
Cable.exe [Module]
Modules:
        enum [Options]       - Enumerate LDAP
        kerberoast <account> - Kerberoast a potentially supplied account, or everything
        dclist               - List Domain Controllers in the current Domain
        rbcd [Options]       - Write or remove the msDs-AllowedToActOnBehalfOfOtherIdentity attribute
        trusts               - Enumerate Active Directory Domain Trusts in the current Forest
        templates            - Enumerate Active Directory Certificate Services (ADCS) Templates
```

### Enum Module Options
```
Usage: Cable.exe enum [Options]
Options:
        --users         - Enumerate user objects
        --computers     - Enumerate computer objects
        --groups        - Enumerate group objects
        --gpos          - Enumerate Group Policy objects
        --spns          - Enumerate objects with servicePrincipalName set
        --asrep         - Enumerate accounts that do not require Kerberos pre-authentication
        --admins        - Enumerate accounts with adminCount set to 1
        --constrained   - Enumerate accounts with msDs-AllowedToDelegateTo set
        --unconstrained - Enumerate accounts with the TRUSTED_FOR_DELEGATION flag set
        --rbcd          - Enumerate accounts with msDs-AllowedToActOnBehalfOfOtherIdentity set

```

### RBCD Module Options
```
Usage: Cable.exe rbcd [Options]
Options:
        --write                   - Operation to write msDs-AllowedToActOnBehalfOfOtherIdentity
        --delegate-to <account>   - Target account to delegate access to
        --delegate-from <account> - Controller account to delegate from
        --flush <account>         - Operation to flush msDs-AllowedToActOnBehalfOfOtherIdentity on an account
```


