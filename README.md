# ldap-spring-session
LDAP Authentication with Spring Session

Sample Online LDAP Credentials from: https://www.forumsys.com/tutorials/integration-how-to/ldap/online-ldap-test-server/

## Login API: 

  URL : http://localhost:8080/login 

  Request Type: POST

  Response: 'session id'
  
  
## User API

  URL : http://localhost:8080/users (append token in the header) 
```bash
 token: 'session id'
```

  Request Type: GET

  Response: SUCCESS
