package com.blue2factor.authentication;

import java.security.PrivateKey;

import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class Blue2FactorJakarta extends Blue2Factor {
	/**
	 * should be called at the top of every page protected by Blue2Factor. Validates
	 * the user has access and update the cookies.
	 * 
	 * @param request    - spring request obj
	 * @param response   - spring response obj
	 * @param companyId  - found on https://secure.blue2factor.com
	 * @param privateKey - corresponds to public key that was uploaded to
	 *                   https://secure.blue2factor.com
	 * @return true if authenticated
	 */
	@Override
	public boolean authenticateAndSecure(HttpServletRequest request, HttpServletResponse response, String companyId,
			PrivateKey privateKey) {
		boolean valid = authenticate(request, companyId, privateKey);
		if (valid) {
			setB2fCookies(response);
		}
		return valid;
	}

	/**
	 * gets the jwt and other cookie and uses them to authenticate
	 * 
	 * @param httpRequest - spring request obj
	 * @param companyId   - found on https://secure.blue2factor.com
	 * @param privateKey  - corresponds to public key that was uploaded to
	 *                    https://secure.blue2factor.com
	 * @return true if authenticated
	 */
	public boolean authenticate(HttpServletRequest request, String companyId, PrivateKey privateKey) {
		String jwt = getPostOrCookieValue(request);
		String currentUrl = getCurrentUrl(request);
		String b2fSetup = this.getB2fSetup(request);
		B2fAuthResponse b2fAuth = authenticate(currentUrl, jwt, b2fSetup, companyId, privateKey);

		this.cookie = b2fAuth.getB2fCookie();
		this.b2fSetup = b2fAuth.getB2fSetup();
		this.redirect = b2fAuth.getRedirect();
		return b2fAuth.isAuthenticated();
	}

	/**
	 * gets the B2F_AUTHN from either a POST or cookie
	 * 
	 * @param request
	 * @return
	 */
	private String getPostOrCookieValue(HttpServletRequest request) {
		String jwt = getRequestValue(request, "B2F_AUTHN");
		if (isEmpty(jwt)) {
			jwt = getCookie(request, "B2F_AUTHN");
		}
		return jwt;
	}

	/**
	 * get a value from a POST
	 * 
	 * @param request
	 * @param value
	 * @return the value or null
	 */
	private String getRequestValue(HttpServletRequest request, String value) {
		String requestValue = null;
		if (request.getParameter(value) == null) {
			requestValue = (String) request.getAttribute(value);
		} else {
			requestValue = request.getParameter(value).trim();
		}
		if (requestValue != null) {
			requestValue = requestValue.replace("%2B", "+");
		}
		return requestValue;
	}

	/**
	 * get a cookie by the name
	 * 
	 * @param request
	 * @param cookieName
	 * @return String or null
	 */
	private String getCookie(HttpServletRequest request, String cookieName) {
		String value = null;
		Cookie[] cookies = request.getCookies();
		if (cookies != null && cookies.length > 0) {
			for (Cookie cookie : cookies) {
				if (cookie.getName().equals(cookieName)) {
					value = cookie.getValue();
					break;
				}

			}
		}
		return value;
	}

	/**
	 * get the current url for spring web server
	 * 
	 * @param request
	 * @return this url
	 */
	private String getCurrentUrl(HttpServletRequest request) {
		return request.getRequestURL().toString() + "?" + request.getQueryString();
	}

	/**
	 * get the b2fSetup value from a form if it exists
	 * 
	 * @param request
	 * @return String or null
	 */
	private String getB2fSetup(HttpServletRequest request) {
		return getRequestValue(request, "b2fSetup");
	}

	/**
	 * set a spring cookie
	 * 
	 * @param httpResponse
	 * @param cookieName
	 * @param value
	 * @param days
	 * @param httpOnly
	 */
	private void setCookie(HttpServletResponse httpResponse, String cookieName, String value, int days,
			boolean httpOnly) {
		Cookie cookie = new Cookie(cookieName, value);
		cookie.setMaxAge(60 * 60 * 24 * days);
		cookie.setSecure(true);
		cookie.setPath("/");
		cookie.setHttpOnly(httpOnly);
		httpResponse.addCookie(cookie);
	}

	/**
	 * for spring web server, set the cookies needed by b2f
	 * 
	 * @param response - spring response obj
	 * @return spring - same thing that came in but with a cookie
	 */
	public void setB2fCookies(HttpServletResponse response) {
		if (!isEmpty(this.b2fSetup)) {
			setCookie(response, "b2fSetup", this.b2fSetup, 1, false);
		}
		if (!isEmpty(this.cookie)) {
			setCookie(response, "B2F_AUTHN", this.cookie, 1, true);
		}
	}

	/**
	 * Redirects after failure when using spring
	 * 
	 * @param httpServletResponse - spring response obj
	 * @return response with redirect
	 */
	public void setRedirect(ServletResponse response) {
		HttpServletResponse httpResponse = (HttpServletResponse) response;
		httpResponse.setHeader("Location", this.getRedirect());
		httpResponse.setStatus(302);
	}

	/**
	 * Should be called when ever a user signs out
	 * 
	 * @param httpServletResponse - spring response obj
	 * @param companyId           - from https://secure.blue2factor.com
	 * @return spring response obj with redirect to signout
	 */
	public void setSignout(ServletResponse response, String companyId) {
		HttpServletResponse httpResponse = (HttpServletResponse) response;
		httpResponse.setHeader("Location", this.getSignout(companyId));
		httpResponse.setStatus(302);
	}

}
