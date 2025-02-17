+++
title = "token"
chapter = false
weight = 10
hidden = false
+++

## Summary
Allows you to generate impersonation tokens
  
- Needs Admin: False  
- Version: 1  
- Author: @checkymander  

### Arguments

#### Username

- Description: The username to authenticate to the host with
- Required: True
- ParameterGroup: Default

#### Password

- Description: The password for the user
- Required: True
- ParameterGroup: Default

#### Domain

- Description: The domain to authenticate to
- Required: True
- ParameterGroup: Default

#### Name

- Description: A descriptive name to give to the token
- Required: True
- ParameterGroup: Default

#### netonly

- Description: Determine whether to use an interactive or netlogon
- Required: False
- ParameterGroup: Default

## Usage

```
    Create a new token for a domain user:
    token make -username <user> -password <password> -domain <domain> -netonly true -name <descriptive name>
    token make -username myuser@contoso.com -password P@ssw0rd -netonly true
    token make -username myuser -password P@ssword -domain contoso.com -netonly false
    
    Create a new token for a local user:
    token make -username mylocaladmin -password P@ssw0rd! -domain . -netonly true
    
    Impersonate a created token    
    token impersonate -name <descriptive name>
    
    Stop impersonating, token can be re-used later
    token revert
```

## Detailed Summary
