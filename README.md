# Cable
Simple Active Directory enumeration and exploitation tool.

## Usage
```
Modules:
        enum [options] - Enumerate LDAP
        kerberoast [account] - Kerberoast a potentially supplied account, otherwise roast everything
        dclist - List Domain Controllers in the current Domain
        rbcd [options] - Read or write msDs-AllowedToActOnBehalfOfOtherIdentity on a target account
```
### Enum Module Options
```
Options:
        --users - Enumerate user objects
        --computers - Enumerate computer objects
        --spns - Enumerate objects with servicePrincipalName set
        --dclist - Enumerate domain controller objects
        --admins - Enumerate accounts with adminCount set to 1
        --constrained - Enumerate accounts with msDs-AllowedToDelegateTo set
        --unconstrained - Enumerate accounts with the TRUSTED_FOR_DELEGATION flag set
```

### RBCD Module Options
```
Options:
        --delegate-to - Target account to delegate access to
        --delegate-from - Controller account to delegate from
        --write - Operation
```

## Showcase
![image](https://github.com/user-attachments/assets/7f4c072f-4f9a-49ba-ab1a-5eceba5056df)

![image](https://github.com/user-attachments/assets/f897cc60-5abc-4018-b2f8-bbd9789242fa)

![image](https://github.com/user-attachments/assets/33b0ff6a-55b7-4da3-a6a3-b167bc4f7757)


## TODO
- Enumerate trust relationships
