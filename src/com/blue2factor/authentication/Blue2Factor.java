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
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.apache.http.util.TextUtils;
import org.json.JSONObject;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
//import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.JwtParserBuilder;
import io.jsonwebtoken.Jwts;

/**
 * The main class for validating Blue2Factor authentication on a Java web server
 * 
 * @author cjm
 *
 */
public class Blue2Factor {
    String secureUrl = "https://secure.blue2factor.com";
    String b2fLogoutUrl = secureUrl + "/logout";
    int SUCCESS = 0;
    int FAILURE = 1;
    int EXPIRED = -1;
    String currentJwt = null;
    String b2fSetup = null;
    String cookie = null;
    private String redirect;

    /**
     * If used without Spring this is the top most call
     * 
     * @param currentUrl - where the browser is
     * @param jwt        - from a POST or COOKIE
     * @param b2fSetup   - from POST - can be null
     * @param companyId  - from https://secure.blue2factor.com
     * @param loginUrl   - from https://secure.blue2factor.com
     * @param privateKey - corresponds to public key that was uploaded to
     *                   https://secure.blue2factor.com
     * @return a b2fAuthResponse with has authenticated, b2fCookie, redirect,b2fSetup;
     */
    public B2fAuthResponse authenticate(String currentUrl, String jwt, String b2fSetup,
            String companyId, String loginUrl, PrivateKey privateKey) {
        B2fAuthResponse authResponse;
        if (notEmpty(jwt)) {
            OutcomeAndToken outcomeAndToken = b2fAuthorized(jwt, companyId, loginUrl, privateKey);
            if (outcomeAndToken.isSuccess()) {
                authResponse = new B2fAuthResponse(true, outcomeAndToken.getToken(), null);
            } else {
                print("redirecting to " + this.getFailureUrl(companyId));
                authResponse = new B2fAuthResponse(false, outcomeAndToken.getToken(),
                        this.getFailureUrl(companyId));
            }
        } else {
            print("jwt was empty");
            String redirectSite = this.getResetUrl(companyId) + "?url=" + urlEncode(currentUrl);
            print("setting redirect to " + redirectSite);
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
    public HttpServletResponse getRedirectSpring(HttpServletResponse httpServletResponse) {
        httpServletResponse.setHeader("Location", this.getRedirect());
        httpServletResponse.setStatus(302);
        return httpServletResponse;
    }

    /**
     * Should be called when ever a user signs out
     * 
     * @param httpServletResponse - spring response obj
     * @param companyId           - from https://secure.blue2factor.com
     * @return spring response obj with redirect to signout
     */
    public HttpServletResponse getSignoutSpring(HttpServletResponse httpServletResponse,
            String companyId) {
        httpServletResponse.setHeader("Location", this.getSignout(companyId));
        httpServletResponse.setStatus(302);
        return httpServletResponse;
    }

    /**
     * should be called at the top of every Spring page protected by Blue2Factor
     * 
     * @param httpRequest - spring request obj
     * @param companyId   - found on https://secure.blue2factor.com
     * @param loginUrl    - found on https://secure.blue2factor.com
     * @param privateKey  - corresponds to public key that was uploaded to
     *                    https://secure.blue2factor.com
     * @return true if authenticated
     */
    public boolean authenticateSpring(HttpServletRequest httpRequest, String companyId,
            String loginUrl, PrivateKey privateKey) {
        String jwt = getPostOrCookieValue(httpRequest);
        String currentUrl = getCurrentUrl(httpRequest);
        String b2fSetup = this.getB2fSetup(httpRequest);
        B2fAuthResponse b2fAuth = authenticate(currentUrl, jwt, b2fSetup, companyId, loginUrl,
                privateKey);

        this.cookie = b2fAuth.getB2fCookie();
        this.b2fSetup = b2fAuth.getB2fSetup();
        this.redirect = b2fAuth.getRedirect();
        return b2fAuth.authenticated;
    }

    /**
     * for spring web server, set the cookies needed by b2f
     * 
     * @param response - spring response obj
     * @return spring - same thing that came in but with a cookie
     */
    public HttpServletResponse setB2fCookies(HttpServletResponse response) {
        if (!isEmpty(this.b2fSetup)) {
//            print("setting b2fSetup to " + this.b2fSetup);
            response = setCookie(response, "b2fSetup", this.b2fSetup, 1, false);
        }
        if (!isEmpty(this.cookie)) {
            response = setCookie(response, "B2F_AUTHN", this.cookie, 1, true);
        }
        return response;
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
     * @return spring response object
     */
    private HttpServletResponse setCookie(HttpServletResponse httpResponse, String cookieName,
            String value, int days, boolean httpOnly) {
        Cookie cookie = new Cookie(cookieName, value);
        cookie.setMaxAge(60 * 60 * 24 * days);
        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setHttpOnly(httpOnly);
        httpResponse.addCookie(cookie);
        return httpResponse;
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
    private OutcomeAndToken b2fAuthorized(String jwt, String companyId, String landingPageUrl,
            PrivateKey privateKey) {
        OutcomeAndToken outcomeAndToken;
        int tokenVal = tokenIsValid(jwt, companyId, landingPageUrl);
        if (tokenVal == this.SUCCESS) {
            print("token was valid");
            outcomeAndToken = new OutcomeAndToken(true, jwt);
        } else {
            if (tokenVal == this.EXPIRED) {
                print("token wasn't valid, will attempt to get a new one");
                outcomeAndToken = this.getNewToken(jwt, companyId, landingPageUrl, privateKey);
            } else {
                outcomeAndToken = new OutcomeAndToken(false, null);
            }
        }
        return outcomeAndToken;
    }

    /**
     * see if a jwt is valid
     * 
     * @param jwt
     * @param companyId
     * @param loginUrl
     * @return true if valid
     */
    private int tokenIsValid(String jwt, String companyId, String loginUrl) {
        int outcome = this.FAILURE;
        if (notEmpty(jwt)) {
            String x5uHeader = getJwtHeaderValue(jwt, "x5u");
            print("publicKeyUrl: " + x5uHeader);
            PublicKey publicKey = getPublicKeyFromUrl(x5uHeader);
            if (publicKey != null) {
                Claims claims = decryptJwt(jwt, publicKey);
                if (claims != null) {
                    print("claims were found");
                    Date exp = claims.getExpiration();
                    Date notBefore = claims.getNotBefore();
                    String issuer = claims.getIssuer();
                    String audience = claims.getAudience();
                    String jwtTokenId = claims.getId();
                    Date now = new Date();
                    if (exp.after(now)) {
                        if (now.after(notBefore)) {
                            if (notEmpty(jwtTokenId)) {
                                if (issuer.equals(this.getIssuer(companyId))) {
                                    if (audience.equals(loginUrl)) {
                                        print("token is valid");
                                        outcome = this.SUCCESS;
                                    } else {
                                        print("audience violated: " + audience);
                                    }
                                } else {
                                    print("issuer violated: " + issuer);
                                }
                            } else {
                                print("claimsId was empty");
                            }
                        } else {
                            print("notBefore violated");
                        }
                    } else {
                        outcome = this.EXPIRED;
                        print("exp violated");
                    }
                } else {
                    print("claims were null");
                }
            }
        } else {
            print("token was null");
        }

        return outcome;
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
    private OutcomeAndToken getNewToken(String jwt, String companyId, String landingPageUrl,
            PrivateKey privateKey) {
        boolean success = false;
        String newJwt = null;
        try {
            String signature = signString(privateKey, jwt);
            String response = sendGet(this.getEndpoint(companyId), jwt + "&" + signature);
            print("newToken response: " + response);
            if (response != null) {
                JSONObject json = new JSONObject(response);
                if (json.getInt("outcome") == this.SUCCESS) {
                    newJwt = json.getString("token");
                    success = tokenIsValid(newJwt, companyId, landingPageUrl) == this.SUCCESS;
                } else {
                    print("new TokenFailed: " + json.getInt("outcome"));
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
        return new OutcomeAndToken(success, newJwt);
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
            throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeyException,
            SignatureException {
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
            print("Expired key, setting claims");
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
            print("responseCode: " + responseCode);
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
            print("header: " + jwtArray[0]);
            Base64.Decoder decoder = Base64.getUrlDecoder();
            String header = new String(decoder.decode(jwtArray[0]));
            print("header decoded: " + header);
            String[] headerArray = header.split("\"" + headerStr + "\":");
            if (headerArray.length == 2) {
                String headerArray2[] = headerArray[1].split("}");
                String headerArray3[] = headerArray2[0].split(",");
                headerVal = removeQuotes(headerArray3[0]);
            }
        }
        print(headerStr + ": " + headerVal);
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
                new Blue2Factor().print(e);
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
        print(stacktrace);
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
            print(text + " is not empty");
            if (!text.equals("null")) {
                notEmpty = true;
            }
        }
        return notEmpty;
    }

    /**
     * print to console
     * 
     * @param text
     */
    private void print(String text) {
        System.out.println(new Date() + ": " + text);
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
        return secureUrl + "/SAML2/SSO/" + companyId + "/Token";
    }

    /**
     * Get the failure url base on the companyId
     * 
     * @param companyId
     * @return url as string
     */
    private String getFailureUrl(String companyId) {
        return secureUrl + "/failure/" + companyId + "/recheck";
    }

    /**
     * Get the reset url based on he companyId
     * 
     * @param companyId
     * @return url as string
     */
    private String getResetUrl(String companyId) {
        return secureUrl + "/failure/" + companyId + "/reset";
    }

    /**
     * get the issue for the JWT
     * 
     * @param companyId
     * @return issuer in jwt as string
     */
    private String getIssuer(String companyId) {
        return secureUrl + "/SAML2/SSO/" + companyId + "/EntityId";
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
        return secureUrl + "/SAML2/SSO/" + companyId + "/Signout";
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
            print("update token");
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
    private class OutcomeAndToken {
        private boolean outcome;
        private String token;

        OutcomeAndToken(boolean outcome, String token) {
            this.outcome = outcome;
            this.token = token;
        }

        public boolean isSuccess() {
            return outcome;
        }

        public String getToken() {
            return token;
        }
    }
}
