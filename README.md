# Get-LockoutStatus

This module allows you to get a complete view of an Active Directory account's current status.

Inspired by the Microsoft [LockoutStatus.exe](https://www.microsoft.com/en-us/download/details.aspx?id=15201) tool.

## Example

    PS C:\> Get-LockoutStatus bob
    
    
    User     : bob (Bob Masters)
    Expired  : True (31.10.2015)
    Disabled : False
    
    
    DomainController     Locked BadPwdCount LastLock               LastBadPwd             PwdExpired
    ----------------     ------ ----------- --------               ----------             ----------
    mydc                 False  0           1.1.2016 16:15:00      1.1.2016 16:14:50      False (set 1.1.2016 13:14:37)
    
    
