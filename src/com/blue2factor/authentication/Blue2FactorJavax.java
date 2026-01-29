package com.blue2factor.authentication;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;

import javax.net.ssl.HttpsURLConnection;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.apache.http.util.TextUtils;
import org.json.JSONObject;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.JwtParserBuilder;
import io.jsonwebtoken.Jwts;

/**
 * The main class for validating Blue2Factor authentication on a Java web server
 * if using javax
 * 
 * @author cjm
 *
 */
public class Blue2FactorJavax {
	String currentJwt = null;
	String b2fSetup = null;
	String cookie = null;
	private String redirect;
	private String failureUrl;

	/**
	 * should be called at the top of every page protected by Blue2Factor. Validates
	 * the user has access and update the cookies.
	 * 
	 * @param request    - spring request obj
	 * @param response   - spring response obj
	 * @param companyId  - found on https://secure.blue2factor.com
	 * @param loginUrl   - found on https://secure.blue2factor.com
	 * @param privateKey - corresponds to public key that was uploaded to
	 *                   https://secure.blue2factor.com
	 * @return true if authenticated
	 */
	public boolean authenticateAndSecure(ServletRequest request, ServletResponse response, String companyId,
			PrivateKey privateKey) {
		HttpServletResponse httpResponse = (HttpServletResponse) response;
		HttpServletRequest httpRequest = (HttpServletRequest) request;
		boolean valid = authenticate(httpRequest, companyId, privateKey);
		if (valid) {
			setB2fCookies(httpResponse);
		}
		return valid;
	}

	/**
	 * gets the jwt and other cookie and uses them to authenticate
	 * 
	 * @param httpRequest - spring request obj
	 * @param companyId   - found on https://secure.blue2factor.com
	 * @param loginUrl    - found on https://secure.blue2factor.com
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
		return b2fAuth.authenticated;
	}

	/**
	 * authenticates with the B2fServer
	 * 
	 * @param currentUrl - where the browser is
	 * @param jwt        - from a POST or COOKIE
	 * @param b2fSetup   - from POST - can be null
	 * @param companyId  - from https://secure.blue2factor.com
	 * @param privateKey - corresponds to public key that was uploaded to
	 *                   https://secure.blue2factor.com
	 * @return a b2fAuthResponse with has authenticated, b2fCookie,
	 *         redirect,b2fSetup;
	 */
	public B2fAuthResponse authenticate(String currentUrl, String jwt, String b2fSetup, String companyId,
			PrivateKey privateKey) {
		B2fAuthResponse authResponse;
		if (notEmpty(jwt)) {
			OutcomeTokenAndUrl outcomeTokenAndUrl = b2fAuthorized(jwt, companyId, privateKey);
			if (outcomeTokenAndUrl.isSuccess()) {
				authResponse = new B2fAuthResponse(true, outcomeTokenAndUrl.getToken(), null);
			} else {
				failureUrl = this.getFailureUrl(companyId) + "?url=" + urlEncode(currentUrl);
				Blue2Factor.print("redirecting to " + failureUrl);
				authResponse = new B2fAuthResponse(false, outcomeTokenAndUrl.getToken(), failureUrl);
			}
		} else {
			Blue2Factor.print("jwt was empty");
			String redirectSite = this.getResetUrl(companyId) + "?url=" + urlEncode(currentUrl);
			Blue2Factor.print("setting redirect to " + redirectSite);
			authResponse = new B2fAuthResponse(false, null, redirectSite);
		}
		authResponse.setB2fSetup(b2fSetup);
		return authResponse;
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
	 * is a string empty?
	 * 
	 * @param text
	 * @return true if string is empty
	 */
	private boolean isEmpty(String text) {
		boolean empty = false;
		if (text == null) {
			empty = true;
		} else {
			if (text.length() == 0 || text.equals("null")) {
				empty = true;
			}
		}
		return empty;
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
//        print("requestVal: " + value + " = " + requestValue);
		return requestValue;
	}

	/**
	 * See if a user is authorized
	 * 
	 * @param jwt
	 * @param companyId
	 * @param landingPageUrl
	 * @param privateKey
	 * @return an outcome and new jwt if successful
	 */
	private OutcomeTokenAndUrl b2fAuthorized(String jwt, String companyId, PrivateKey privateKey) {
		OutcomeTokenAndUrl outcomeTokenAndUrl;
		OutcomeAndUrl outcomeAndUrl = tokenIsValid(jwt, companyId);
		if (outcomeAndUrl.getOutcome() == Blue2Factor.SUCCESS) {
			Blue2Factor.print("token was valid");
			outcomeTokenAndUrl = (OutcomeTokenAndUrl) outcomeAndUrl;
		} else {
			if (outcomeAndUrl.getOutcome() == Blue2Factor.EXPIRED) {
				Blue2Factor.print("token wasn't valid, will attempt to get a new one");
				outcomeTokenAndUrl = this.getNewToken(jwt, companyId, privateKey);
			} else {
				outcomeTokenAndUrl = (OutcomeTokenAndUrl) outcomeAndUrl;
			}
		}
		return outcomeTokenAndUrl;
	}

	/**
	 * see if a jwt is valid
	 * 
	 * @param jwt
	 * @param companyId
	 * @param loginUrl
	 * @return true if valid
	 */
	private OutcomeAndUrl tokenIsValid(String jwt, String companyId) {
		int outcome = Blue2Factor.FAILURE;
		String url = null;
		if (notEmpty(jwt)) {
			String x5uHeader = getJwtHeaderValue(jwt, "x5u");
			Blue2Factor.print("publicKeyUrl: " + x5uHeader);
			PublicKey publicKey = getPublicKeyFromUrl(x5uHeader);
			if (publicKey != null) {
				Claims claims = decryptJwt(jwt, publicKey);
				if (claims != null) {
					Blue2Factor.print("claims were found");
					Date exp = claims.getExpiration();
					Date notBefore = claims.getNotBefore();
					String issuer = claims.getIssuer();
					String audience = claims.getAudience();
					String jwtTokenId = claims.getId();
					Date now = new Date();
					if (exp.after(now)) {
						Blue2Factor.print("expires " + exp);
						if (now.after(notBefore)) {
							if (notEmpty(jwtTokenId)) {
								url = this.getIssuer(companyId);
								if (!TextUtils.isEmpty(url) && issuer.equals(url)) {
									if (audience.equals(url)) {
										Blue2Factor.print("token is valid");
										outcome = Blue2Factor.SUCCESS;
									} else {
										Blue2Factor.print("audience violated: " + audience);
									}
								} else {
									Blue2Factor.print("issuer violated: " + issuer);
								}
							} else {
								Blue2Factor.print("claimsId was empty");
							}
						} else {
							Blue2Factor.print("notBefore violated");
						}
					} else {
						outcome = Blue2Factor.EXPIRED;
						Blue2Factor.print("exp violated");
					}
				} else {
					Blue2Factor.print("claims were null");
				}
			}
		} else {
			Blue2Factor.print("token was null");
		}

		return new OutcomeAndUrl(outcome, url);
	}

	/**
	 * get a new token from b2f server
	 * 
	 * @param jwt
	 * @param companyId
	 * @param landingPageUrl
	 * @param privateKey
	 * @return and outcome and a token if successful
	 */
	private OutcomeTokenAndUrl getNewToken(String jwt, String companyId, PrivateKey privateKey) {
		boolean success = false;
		String newJwt = null;
		String url = null;
		try {
			String signature = signString(privateKey, jwt);
			String response = sendGet(this.getEndpoint(companyId), jwt + "&" + signature);
			Blue2Factor.print("newToken response: " + response);
			if (response != null) {
				JSONObject json = new JSONObject(response);
				if (json.getInt("outcome") == Blue2Factor.SUCCESS) {
					newJwt = json.getString("token");
					OutcomeAndUrl outcomeAndUrl = tokenIsValid(newJwt, companyId);
					success = outcomeAndUrl.isSuccess();
					url = outcomeAndUrl.getUrl();
				} else {
					Blue2Factor.print("new TokenFailed: " + json.getInt("outcome"));
				}
			}
		} catch (InterruptedException e) {
			print(e);
		} catch (IOException e) {
			print(e);
		} catch (InvalidKeyException e) {
			print(e);
		} catch (NoSuchAlgorithmException e) {
			print(e);
		} catch (SignatureException e) {
			print(e);
		}
		return new OutcomeTokenAndUrl(success, newJwt, url);
	}

	/**
	 * Sign a string with a private key
	 * 
	 * @param privateKey
	 * @param stringToSign
	 * @return the signature
	 * @throws NoSuchAlgorithmException
	 * @throws UnsupportedEncodingException
	 * @throws InvalidKeyException
	 * @throws SignatureException
	 */
	private String signString(PrivateKey privateKey, String stringToSign)
			throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeyException, SignatureException {
		byte[] data = stringToSign.getBytes(UTF_8);
		Signature sig = Signature.getInstance("SHA256withRSA");
		sig.initSign(privateKey);
		sig.update(data);
		byte[] signatureBytes = sig.sign();
		String encryptedValue = Base64.getEncoder().encodeToString(signatureBytes);
		return encryptedValue;
	}

	/**
	 * decrypt a jwt into claims
	 * 
	 * @param jwsString
	 * @param publicKey
	 * @return the claims
	 */
	private Claims decryptJwt(String jwsString, PublicKey publicKey) {
		Jws<Claims> jws = null;
		Claims claims = null;
		try {
			if (publicKey != null) {
				JwtParserBuilder parseBuilder = Jwts.parserBuilder();
				JwtParser parser = parseBuilder.setSigningKey(publicKey).build();
				jws = parser.parseClaimsJws(jwsString);
				claims = jws.getBody();
			}
		} catch (ExpiredJwtException e) {
			Blue2Factor.print("Expired key, setting claims");
			print(e);
			claims = e.getClaims();
		} catch (JwtException ex) {
			print(ex);
		}
		return claims;
	}

	/**
	 * go to a url and return the value as public key
	 * 
	 * @param x5uHeader
	 * @return a publicKey or null
	 */
	private PublicKey getPublicKeyFromUrl(String x5uHeader) {
		PublicKey publicKey = null;
		try {
			String pubKeyStr = sendGet(x5uHeader);
			if (notEmpty(pubKeyStr)) {
				publicKey = stringToJwtPublicKey(pubKeyStr);
			}
		} catch (InterruptedException e) {
			print(e);
		} catch (IOException e) {
			print(e);
		}
		return publicKey;
	}

	/**
	 * set a get request without a token
	 * 
	 * @param urlStr
	 * @return
	 * @throws InterruptedException
	 * @throws IOException
	 */
	private String sendGet(String urlStr) throws InterruptedException, IOException {
		return sendGet(urlStr, null);
	}

	/**
	 * send a url request
	 * 
	 * @param urlStr
	 * @param jwt
	 * @return the response text
	 * @throws InterruptedException
	 * @throws IOException
	 */
	private String sendGet(String urlStr, String jwt) throws InterruptedException, IOException {
		InputStream in = null;
		HttpsURLConnection conn = null;
		String result = null;
		try {
			URL url = new URL(urlStr);
			conn = (HttpsURLConnection) url.openConnection();
			if (jwt != null) {
				conn.setRequestProperty("Authorization", "Bearer " + jwt);
			}
			conn.setConnectTimeout(25000);
			conn.setRequestProperty("Cache-Control", "no-cache");
			conn.setRequestProperty("Pragma", "no-cache");
			conn.setRequestProperty("Accept-Charset", StandardCharsets.UTF_8.toString());

			conn.setUseCaches(false);
			conn.setRequestMethod("GET");
			int responseCode = conn.getResponseCode();
			Blue2Factor.print("responseCode: " + responseCode);
			if (responseCode == 200) {
				// read the response
				in = new BufferedInputStream(conn.getInputStream());
				result = org.apache.commons.io.IOUtils.toString(in, StandardCharsets.UTF_8);
			}
		} catch (Exception e) {
			print(e);
		}
		if (in != null) {
			in.close();
		}
		if (conn != null) {
			conn.disconnect();
		}
		return result;
	}

	/**
	 * convert a string into a public Key
	 * 
	 * @param publicKeyStr
	 * @return a publicKey or null
	 */
	private PublicKey stringToJwtPublicKey(String publicKeyStr) {
		PublicKey generatedPublic = null;
		String keyString = publicKeyStr.replace("\n", "");
		try {
			KeyFactory kf = KeyFactory.getInstance("RSA");
			byte[] decoded = Base64.getDecoder().decode(keyString);
			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decoded);
			generatedPublic = kf.generatePublic(keySpec);
		} catch (Exception e) {
			print(e);
		}
		return generatedPublic;
	}

	/**
	 * get the header from a jwt
	 * 
	 * @param jwt
	 * @param headerStr
	 * @return the unencrypted header?
	 */
	private String getJwtHeaderValue(String jwt, String headerStr) {
		String headerVal = null;
		String[] jwtArray = jwt.split("\\.");
		if (jwtArray.length > 1) {
			Blue2Factor.print("header: " + jwtArray[0]);
			Base64.Decoder decoder = Base64.getUrlDecoder();
			String header = new String(decoder.decode(jwtArray[0]));
			Blue2Factor.print("header decoded: " + header);
			String[] headerArray = header.split("\"" + headerStr + "\":");
			if (headerArray.length == 2) {
				String headerArray2[] = headerArray[1].split("}");
				String headerArray3[] = headerArray2[0].split(",");
				headerVal = removeQuotes(headerArray3[0]);
			}
		}
		Blue2Factor.print(headerStr + ": " + headerVal);
		return headerVal;
	}

	/**
	 * Encode a string for a url
	 * 
	 * @param url
	 * @return encoded string
	 */
	private static String urlEncode(String url) {
		String newUrl = "";
		if (url != null) {
			try {
				newUrl = URLEncoder.encode(url, StandardCharsets.UTF_8.name());
			} catch (UnsupportedEncodingException e) {
				new Blue2FactorJavax().print(e);
			}
		}
		return newUrl;
	}

	/**
	 * Print an exception
	 * 
	 * @param e
	 */
	private void print(Exception e) {
		String stacktrace = ExceptionUtils.getStackTrace(e);
		Blue2Factor.print(stacktrace);
	}

	/**
	 * return is a string empty
	 * 
	 * @param text
	 * @return true if the input is not empty
	 */
	private boolean notEmpty(String text) {
		boolean notEmpty = false;
		if (!TextUtils.isEmpty(text)) {
			Blue2Factor.print(text + " is not empty");
			if (!text.equals("null")) {
				notEmpty = true;
			}
		}
		return notEmpty;
	}

	/**
	 * remove double and single quotes from a string
	 * 
	 * @param text
	 * @return string with quotes removed
	 */
	private String removeQuotes(String text) {
		return text.replace("\"", "").replace("'", "");
	}

	/**
	 * Get the new token url based on the companyID
	 * 
	 * @param companyId
	 * @return token refresh url as string
	 */
	private String getEndpoint(String companyId) {
		return Blue2Factor.secureUrl + "/SAML2/SSO/" + companyId + "/Token";
	}

	/**
	 * Get the failure url base on the companyId
	 * 
	 * @param companyId
	 * @return url as string
	 */
	private String getFailureUrl(String companyId) {
		return Blue2Factor.secureUrl + "/failure/" + companyId + "/recheck";
	}

	public String getFailureUrl() {
		return failureUrl;
	}

	/**
	 * Get the reset url based on he companyId
	 * 
	 * @param companyId
	 * @return url as string
	 */
	private String getResetUrl(String companyId) {
		return Blue2Factor.secureUrl + "/failure/" + companyId + "/reset";
	}

	/**
	 * get the issue for the JWT
	 * 
	 * @param companyId
	 * @return issuer in jwt as string
	 */
	private String getIssuer(String companyId) {
		return Blue2Factor.secureUrl + "/SAML2/SSO/" + companyId + "/EntityId";
	}

	/**
	 * get the url that failures should be sent to
	 * 
	 * @return redirect url as a string
	 */
	public String getRedirect() {
		return redirect;
	}

	/**
	 * get the signout url
	 * 
	 * @param companyId
	 * @return
	 */
	private String getSignout(String companyId) {
		return Blue2Factor.secureUrl + "/SAML2/SSO/" + companyId + "/Signout";
	}

	/**
	 * Object to hold a bunch of values that are needed to respond
	 * 
	 * @author cjm10
	 *
	 */
	public class B2fAuthResponse {
		private boolean authenticated;
		private String b2fCookie;
		private String redirect;
		private String b2fSetup;

		/**
		 * Initializer
		 * 
		 * @param authenticated - auth success or failure
		 * @param token         - a jwt
		 * @param redirect      - a url to follow when failure occurs
		 */
		public B2fAuthResponse(boolean authenticated, String token, String redirect) {
			this.authenticated = authenticated;
			this.b2fCookie = token;
			this.redirect = redirect;
		}

		/**
		 * is the user b2f allowed
		 * 
		 * @return true if authenticated
		 */
		public boolean isAuthenticated() {
			return authenticated;
		}

		/**
		 * get the jwt which will be stored as a cookie
		 * 
		 * @return the newest jwt
		 */
		public String getB2fCookie() {
			return b2fCookie;
		}

		/**
		 * where the user should be sent on failure
		 * 
		 * @return the redirect url
		 */
		public String getRedirect() {
			return redirect;
		}

		/**
		 * set the jwt as a cookie
		 * 
		 * @param b2fCookie - the jwt
		 */
		public void setB2fCookie(String b2fCookie) {
			Blue2Factor.print("update token");
			this.b2fCookie = b2fCookie;
		}

		/**
		 * sets setup token
		 * 
		 * @param b2fSetup - string from POST
		 */
		public void setB2fSetup(String b2fSetup) {
			this.b2fSetup = b2fSetup;
		}

		/**
		 * return a setup token
		 * 
		 * @return the setup token
		 */
		public String getB2fSetup() {
			return b2fSetup;
		}
	}

	/**
	 * a Boolean outcome and a jwt if the outcome is true
	 * 
	 * @author cjm10
	 *
	 */
	private class OutcomeTokenAndUrl extends OutcomeAndUrl {
		private String token;

		OutcomeTokenAndUrl(boolean outcomeSuccess, String token, String url) {
			super(outcomeSuccess, url);
			this.token = token;
		}

		OutcomeTokenAndUrl(boolean outcomeSuccess, String token) {
			super(outcomeSuccess, null);
			this.token = token;
		}

		public String getToken() {
			return token;
		}

	}

	private class OutcomeAndUrl {
		private boolean outcomeSuccess;
		private int outcome;
		private String url;

		OutcomeAndUrl(int outcome, String url) {
			this.outcome = outcome;
			this.outcomeSuccess = outcome == Blue2Factor.SUCCESS;
			this.url = url;
		}

		OutcomeAndUrl(boolean outcomeSuccess, String url) {
			this.outcomeSuccess = outcomeSuccess;
			if (outcomeSuccess) {
				outcome = Blue2Factor.SUCCESS;
			} else {
				outcome = Blue2Factor.FAILURE;
			}
			this.url = url;
		}

		public boolean isSuccess() {
			return outcomeSuccess;
		}

		public int getOutcome() {
			return outcome;
		}

		public String getUrl() {
			return url;
		}
	}
}
