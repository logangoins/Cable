# Cable
Cable is a post-exploitation tool used for reconnaissance and Discretionary Access Control List (DACL) focused exploitation of an Active Directory environment. This tool was primarily created to learn more about .NET offensive development in an Active Directory context, while hoping to expand my current knowledge and understanding of Active Directory focused offensive security.

## Usage
```
 ________  ________  ________  ___       _______
|\   ____\|\   __  \|\   __  \|\  \     |\  ___ \
\ \  \___|\ \  \|\  \ \  \|\ /\ \  \    \ \   __/|
 \ \  \    \ \   __  \ \   __  \ \  \    \ \  \_|/__
  \ \  \____\ \  \ \  \ \  \|\  \ \  \____\ \  \_|\ \
   \ \_______\ \__\ \__\ \_______\ \_______\ \_______\
    \|_______|\|__|\|__|\|_______|\|_______|\|_______|

.NET post-exploitation toolkit for Active Directory reconnaissance and exploitation

Cable.exe [Module]
Modules:
        ldap [Options]            - Enumerate LDAP
        dclist                    - List Domain Controllers in the current Domain
        rbcd [Options]            - Write or remove the msDs-AllowedToActOnBehalfOfOtherIdentity attribute
        dacl [Options]            - Read or write Access Control Entries (ACE)s on an object
        trusts                    - Enumerate Active Directory Domain and Forest Trusts
        ca                        - Enumerate any active Active Directory Certifcate Services (ADCS) CA's
        templates                 - Enumerate Active Directory Certificate Services (ADCS) Templates
        user [Options]            - Preform general operations on user accounts
        computer [Options]        - Add and remove computer accounts from the domain
        group [Options]           - Enumerate group membership, add, and remove users from groups

Module Options
ldap:
        /users                    - Enumerate user objects
        /computers                - Enumerate computer objects
        /groups                   - Enumerate group objects
        /spns                     - Enumerate objects with servicePrincipalName set
        /asrep                    - Enumerate accounts that do not require Kerberos pre-authentication
        /admins                   - Enumerate accounts with adminCount set to 1
        /constrained              - Enumerate accounts with msDs-AllowedToDelegateTo set
        /unconstrained            - Enumerate accounts with the TRUSTED_FOR_DELEGATION flag set
        /rbcd                     - Enumerate accounts with msDs-AllowedToActOnBehalfOfOtherIdentity set
        /query:<query>            - Enumerate objects with a custom query
        /filter:"<attr, attr>"    - Enumerate objects for specific attributes

rbcd:
        /write                    - Operation to write msDs-AllowedToActOnBehalfOfOtherIdentity
        /delegate-to:<account>    - Target account to delegate access to
        /delegate-from:<account>  - Controlled account to delegate from
        /flush:<account>          - Operation to flush msDs-AllowedToActOnBehalfOfOtherIdentity on an account

dacl:
        /find                     - Find potentially vulnerable ACEs
        /object:<object>          - Object to perform DACL operations on
        /read                     - Operation to read the objects Access Control Entries (ACE)s
        /write:<permission>       - Write a ACE on the selected object, built in permissions are: GenericAll,GenericWrite,User-Force-Reset-Password,Self-Membership
        /guid:<guid>              - Specify custom GUID for permission or extended right to write on the object, alternative for "--write"
        /account:<account>        - Display access an account has on the target object, or set access to this account on the target object. Example: CORP\jdoe

user:
        /setspn:<value>           - Write to an objects servicePrincipalName attribute
        /removespn:<value>        - Remove a specified value off the servicePrincipalName attribute
        /setasrep                 - Operation to set the DONT_REQ_PREAUTH flag on an objects userAccountControl attribute
        /removeasrep              - Operation to remove the DONT_REQ_PREAUTH flag on an objects userAccountControl attribute
        /user:<account>           - Specify user account to preform operations on
        /password:<password>      - Change an accounts password
        /getgroups                - Operation to enumerate a users current group membership

computer:
        /add                      - Operation to add a computer account object
        /remove                   - Operation to delete a computer account object
        /name:<name>              - Computer name to add or remove
        /password:<passwd>        - Computer account password

group:
        /group:<group>            - The group used for an operation specified
        /add:<account>            - Add a specified account to the group selected
        /remove:<account>         - Remove a specified account from the group selected
        /getusers                 - Operation to enumerate current users in a group

```
