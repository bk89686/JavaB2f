# JavaB2f

This package is used for java webservers that use Blue2Factor

It can be used with Spring or without.

##### With Maven:

```
<dependency>
  <groupId>com.blue2factor.authentication</groupId>
  <artifactId>java-b2f</artifactId>
  <version>1.0.3-SNAPSHOT</version>
</dependency>
```

##### Or on GitHub at [https://github.com/bk89686/JavaB2f](https://github.com/bk89686/JavaB2f)

### To use with Spring:

```
import com.blue2factor.authentication.Blue2Factor;

...
    final String myCompanyId = "COMPANY_ID from https://secure.blue2factor.com"
    final String myLandingPage = "LOGIN_URL that was entered at https://secure.blue2factor.com"

    Blue2Factor b2f = new Blue2Factor();
    
    @RequestMapping(method = { RequestMethod.GET, RequestMethod.POST })
    public String processUrl(HttpServletRequest request, HttpServletResponse httpServletResponse,
            ModelMap model) {
        PrivateKey pk = getPrivateKey();
        if (!b2f.authenticateSpring(httpRequest, myCompanyId, myLandingPage, pk)) {
            return b2f.getRedirectSpring(httpServletResponse);
        }
        httpResponse = b2f.setB2fCookies(httpServletResponse);
        // do what ever you normally do
        return "landingPage";
    }
    
    private PrivateKey getPrivateKey() {
        //your own method to get the private key that corresponds to the public key
        //that you uploaded to https://secure.blue2factor.com
    }
    
    //when a user signs out call:
    return b2f.getSignoutSpring(httpServletResponse, companyId);
    
```

### Or without Spring

```
import com.blue2factor.authentication.Blue2Factor;

...

    final String myCompanyId = "COMPANY_ID from https://secure.blue2factor.com"
    final String myLandingPage = "LOGIN_URL that was entered at https://secure.blue2factor.com"

    Blue2Factor b2f = new Blue2Factor();

    public String processUrl() {
        B2fAuthResponse authResponse = b2f.authenticate(getCurrentUrl(), getJwt(), getB2fSetup() this.myCompanyId,
            this.myLandingPage, getPrivateKey());
        if (!auth.isAuthenticated(){
            //redirect to auth.getRedirect() and return
        }
        //and set cookies with your own method
        setCookie("B2F_AUTHN", auth.getB2fCookie());
        setCookie("b2fSetup", auth.getB2fSetup());
        
        //do what you would normally do
        
    }
    
    private PrivateKey getPrivateKey() {
        //your own method to get the private key that corresponds to the public key
        //that you uploaded to https://secure.blue2factor.com
    }
    
    private String getJwt() {
        //Get B2F_AUTHN which was sent as part of a POST form
        //if it's not there get the value of a cookie name B2F_AUTHN
    }
    
    private String getB2fSetup() {
        //Get b2fSetup which may have been sent as part of a POST form
    }
    
    //when a user signs out
    //redirect to b2f.getSignout(this.myCompanyId);
    
```

for questions, please contact us at (607) 238-3522 or help@blue2factor.com
