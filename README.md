# JavaB2f

This package is used for java webservers that use Blue2Factor

It can be used with Spring or without.

##### With Maven:

```
<dependency>
  <groupId>com.blue2factor.authentication</groupId>
  <artifactId>java-b2f</artifactId>
  <version>1.0.5-SNAPSHOT</version>
</dependency>
```

##### Or on GitHub at [https://github.com/bk89686/JavaB2f](https://github.com/bk89686/JavaB2f)

### To use with Spring:

```
import com.blue2factor.authentication.Blue2Factor;

...
    final String myCompanyId = "COMPANY_ID from https://secure.blue2factor.com"
	final PrivateKey = getPrivateKey();
    Blue2Factor b2f = new Blue2Factor();
    //if using javax rather than jakarta then
    //Blue2FactorJavax b2f = new Blue2FactorJavax();
    
    @RequestMapping(method = { RequestMethod.GET, RequestMethod.POST })
    public String processUrl(HttpServletRequest request, HttpServletResponse httpResponse,
            ModelMap model) {
        if (!b2f.authenticateAndSecure(httpRequest, httpResponse, myCompanyId, pk)) {
            return b2f.getRedirect(httpServletResponse);
        }
        //do whatever you normally do
    }
    
    private PrivateKey getPrivateKey() {
        //your own method to get the private key that corresponds to the public key
        //that you uploaded to https://secure.blue2factor.com
    }
    
    //when a user signs out call:
    return b2f.getSignout(httpServletResponse, companyId);
    
```

### Or without Spring

```
import com.blue2factor.authentication.Blue2Factor;

...

public class MyClass implements Filter

    final String myCompanyId = "COMPANY_ID from https://secure.blue2factor.com"
    final PrivateKey pk = getPrivateKey();
    Blue2Factor b2f = new Blue2Factor();

	@Override
    public void doFilter(ServletRequest request, ServletResponse response, Filter chain) {
        if (!b2f.authenticateAndSecure(httpRequest, httpResponse, myCompanyId, pk)) {
			response.sendRedirect(b2f.getFailureUrl());
        } else {
			//success - do what you normally do
			chain.doFilter(request, response);
		}
    }
    
    //when a user signs out
    //redirect to b2f.getSignout(this.myCompanyId);
    
```

If you aren't using Spring, add this to your web.xml:

```
<filter>
	<filter-name>B2FFilter</filter-name>
	<filter-class>com.blue2factor.Blue2FactorFilter</filter-class>
</filter>
<filter-mapping>
	<filter-name>B2FFilter</filter-name>
	<url-pattern>/admin/*</url-pattern>
<filter-mapping>

```
for questions, please contact us at (607) 238-3522 or help@blue2factor.com
