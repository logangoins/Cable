# Cable
Cable is a simple post-exploitation tool used for enumeration and further exploitation of Active Directory environments. This tool was primarily created to learn more about .NET offensive development in an Active Directory context, while hoping to expand my current knowledge and understanding of Active Directory focusing offensive security.

Cable has a few primary features currently, with high hopes at feature expansion: 
- The ability to request service tickets from accounts registered with a `servicePrincipalName` and format them as part of a Kerberoasting attack. 
- The ability to write and remove the `msDs-AllowedToActOnBehalfOfOtherIdentity` attribute on desired objects, as part of a Resource-Based Constrained Delegation (RBCD) attack. 
- Enumeration of Active Directory Certificate Services (ADCS) certificate templates
- Enumeration of domain trusts configured in the current forest
- Enumeration of domain controllers in the current domain
- General LDAP enumeration with both pre-created queries and the ability to specify custom queries.


## Usage
```
 ________  ________  ________  ___       _______
|\   ____\|\   __  \|\   __  \|\  \     |\  ___ \
\ \  \___|\ \  \|\  \ \  \|\ /\ \  \    \ \   __/|
 \ \  \    \ \   __  \ \   __  \ \  \    \ \  \_|/__
  \ \  \____\ \  \ \  \ \  \|\  \ \  \____\ \  \_|\ \
   \ \_______\ \__\ \__\ \_______\ \_______\ \_______\
    \|_______|\|__|\|__|\|_______|\|_______|\|_______|

Cable.exe [Module]
Modules:
        enum [Options]       - Enumerate LDAP
        kerberoast <account> - Kerberoast a potentially supplied account, or everything
        dclist               - List Domain Controllers in the current Domain
        rbcd [Options]       - Write or remove the msDs-AllowedToActOnBehalfOfOtherIdentity attribute
        trusts               - Enumerate Active Directory Domain Trusts in the current Forest
        templates            - Enumerate Active Directory Certificate Services (ADCS) Templates

Module Options
enum:
        --users          - Enumerate user objects
        --computers      - Enumerate computer objects
        --groups         - Enumerate group objects
        --gpos           - Enumerate Group Policy objects
        --spns           - Enumerate objects with servicePrincipalName set
        --asrep          - Enumerate accounts that do not require Kerberos pre-authentication
        --admins         - Enumerate accounts with adminCount set to 1
        --constrained    - Enumerate accounts with msDs-AllowedToDelegateTo set
        --unconstrained  - Enumerate accounts with the TRUSTED_FOR_DELEGATION flag set
        --rbcd           - Enumerate accounts with msDs-AllowedToActOnBehalfOfOtherIdentity set
        --filter <query> - Enumerate objects with a custom set query

rbcd:
        --write                   - Operation to write msDs-AllowedToActOnBehalfOfOtherIdentity
        --delegate-to <account>   - Target account to delegate access to
        --delegate-from <account> - Controlled account to delegate from
        --flush <account>         - Operation to flush msDs-AllowedToActOnBehalfOfOtherIdentity on an account
```


