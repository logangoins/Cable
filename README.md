# Cable
Cable is a simple post-exploitation tool used for enumeration and further exploitation of Active Directory environments. This tool was primarily created to learn more about .NET offensive development in an Active Directory context, while hoping to expand my current knowledge and understanding of Active Directory focused offensive security.

Cable has a few primary features currently, with high hopes at feature expansion: 
- The ability to request service tickets from accounts registered with a `servicePrincipalName` and place them in a crackable format as part of a Kerberoasting attack. 
- The ability to write and remove the value of the `msDs-AllowedToActOnBehalfOfOtherIdentity` attribute on desired objects, as part of a Resource-Based Constrained Delegation (RBCD) attack. 
- Enumeration of Active Directory Certificate Services (ADCS) CA's and certificate templates.
- Enumeration of domain trusts configured in the current forest.
- Enumeration of domain controllers in the current domain.
- General LDAP enumeration with both pre-created queries and the ability to specify custom queries.
- The ability to perform password changes.
- The ability to set and remove the value of the `servicePrincipalName` attribute on an object, making it kerberoastable and non-kerberoastable respectfully.
- Enumeration of group membership.
- The ability to add and remove accounts from groups.

## Usage
```
 ________  ________  ________  ___       _______
|\   ____\|\   __  \|\   __  \|\  \     |\  ___ \
\ \  \___|\ \  \|\  \ \  \|\ /\ \  \    \ \   __/|
 \ \  \    \ \   __  \ \   __  \ \  \    \ \  \_|/__
  \ \  \____\ \  \ \  \ \  \|\  \ \  \____\ \  \_|\ \
   \ \_______\ \__\ \__\ \_______\ \_______\ \_______\
    \|_______|\|__|\|__|\|_______|\|_______|\|_______|

Active Directory Enumeration and Exploitation tool

Cable.exe [Module]
Modules:
        enum [Options]            - Enumerate LDAP
        kerberoast <account>      - Kerberoast a potentially supplied account, or everything
        dclist                    - List Domain Controllers in the current Domain
        rbcd [Options]            - Write or remove the msDs-AllowedToActOnBehalfOfOtherIdentity attribute
        trusts                    - Enumerate Active Directory Domain Trusts in the current Forest
        ca                        - Enumerate any active Active Directory Certifcate Services (ADCS) CA's
        templates                 - Enumerate Active Directory Certificate Services (ADCS) Templates
        user [Options]            - Preform general operations on user accounts
        group [Options]           - Enumerate group membership, add, and remove users from groups

Module Options
enum:
        --users                   - Enumerate user objects
        --computers               - Enumerate computer objects
        --groups                  - Enumerate group objects
        --gpos                    - Enumerate Group Policy objects
        --spns                    - Enumerate objects with servicePrincipalName set
        --asrep                   - Enumerate accounts that do not require Kerberos pre-authentication
        --admins                  - Enumerate accounts with adminCount set to 1
        --constrained             - Enumerate accounts with msDs-AllowedToDelegateTo set
        --unconstrained           - Enumerate accounts with the TRUSTED_FOR_DELEGATION flag set
        --rbcd                    - Enumerate accounts with msDs-AllowedToActOnBehalfOfOtherIdentity set
        --query <query>           - Enumerate objects with a custom query
        --filter <attr, attr>     - Enumerate objects for specific attributes

rbcd:
        --write                   - Operation to write msDs-AllowedToActOnBehalfOfOtherIdentity
        --delegate-to <account>   - Target account to delegate access to
        --delegate-from <account> - Controlled account to delegate from
        --flush <account>         - Operation to flush msDs-AllowedToActOnBehalfOfOtherIdentity on an account

user:
        --setspn <value>          - Write to an objects servicePrincipalName attribute
        --removespn <value>       - Remove a specified value off the servicePrincipalName attribute
        --user <account>          - Specify user account to preform operations on
        --password <password>     - Change an accounts password

group:
        --getmembership           - Operation to get Active Directory group membership
        --group <group>           - The group used for an operation specified
        --add <account>           - Add a specified account to the group selected
        --remove <account>        - Remove a specified account from the group selected
```


