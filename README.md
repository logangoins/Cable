# Cable
Simple Active Directory enumeration and exploitation tool.

## Usage
```
Modules:
        enum [options] - Enumerate LDAP
        kerberoast [account] - Kerberoast a potentially supplied account, or everything
        dclist - List Domain Controllers in the current Domain
        rbcd [options] - Write or read the msDs-AllowedToActOnBehalfOfOtherIdentity attribute
        trusts - Enumerate Active Directory Domain Trusts in the current Forest
        templates - Enumerate Active Directory Certificate Services (ADCS) Templates
```
### Enum Module Options
```
Options:
        --users - Enumerate user objects
        --computers - Enumerate computer objects
        --groups - Enumerate group objects
        --gpos - Enumerate Group Policy objects
        --spns - Enumerate objects with servicePrincipalName set
        --dclist - Enumerate domain controller objects
        --admins - Enumerate accounts with adminCount set to 1
        --constrained - Enumerate accounts with msDs-AllowedToDelegateTo set
        --unconstrained - Enumerate accounts with the TRUSTED_FOR_DELEGATION flag set
        --rbcd - Enumerate accounts with msDs-AllowedToActOnBehalfOfOtherIdentity set
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

![image](https://github.com/user-attachments/assets/54dbff3c-5309-4922-9453-a89a4530999d)


