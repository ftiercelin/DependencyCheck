package org.owasp.dependencycheck.utils;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.net.URL;
import java.util.Base64;
import java.util.UUID;

import org.apache.hc.client5.http.auth.AuthScope;
import org.apache.hc.client5.http.auth.BearerToken;
import org.apache.hc.client5.http.auth.Credentials;
import org.apache.hc.client5.http.auth.StandardAuthScheme;
import org.apache.hc.client5.http.auth.UsernamePasswordCredentials;
import org.apache.hc.client5.http.impl.auth.BasicCredentialsProvider;
import org.junit.Test;

public class DownloaderAddCredentialsTest {

	@Test
	public void testBaseFunctions() throws Exception {
		String user = UUID.randomUUID().toString();
		String password = UUID.randomUUID().toString();
		String b64 = StandardAuthScheme.BASIC + " " + Base64.getEncoder().encodeToString((user+":"+password).getBytes());
		int start = StandardAuthScheme.BASIC.length() + 1;

		// starts with
		assertTrue(Downloader.startsWith(b64.toCharArray(), StandardAuthScheme.BASIC));
		assertFalse(Downloader.startsWith(b64.toCharArray(), StandardAuthScheme.BEARER));

		// Basic auth
		assertEquals(user, Downloader.getBasicUser(b64.toCharArray(), start));
		assertEquals(password, new String(Downloader.getBasicPassword(b64.toCharArray(), start)));
	}
	
	


	
	

	///////////////////////////////////////////////////
	// test basic auth methods
	///////////////////////////////////////////////////
	
	@Test
	public void testGetBasicCredentials() throws Exception {
		String user = "U-" + UUID.randomUUID().toString();
		String pass = "P-" + UUID.randomUUID().toString();
		String auth = StandardAuthScheme.BASIC + " " + Base64.getEncoder().encodeToString(((user + ":" + pass).getBytes()));

		
		Credentials credentials = Downloader.getBasicCredentialsFromAuthHeader(auth.toCharArray());
		assertNotNull(credentials);
		assertTrue(credentials instanceof UsernamePasswordCredentials);
		assertEquals(user, ((UsernamePasswordCredentials) credentials).getUserName());
		assertEquals(pass, new String(((UsernamePasswordCredentials) credentials).getUserPassword()));
		
		checkBasicException(null);
		checkBasicException("".toCharArray());
		checkBasicException(" ".toCharArray());
		checkBasicException("12323333333333 33".toCharArray());
		auth = StandardAuthScheme.BASIC + " ";
		checkBasicException(auth.toCharArray());
		auth = StandardAuthScheme.BASIC + " !!!!!!!!!!!!!!!!!!!!!!!!";
		checkBasicException(auth.toCharArray());
		auth = StandardAuthScheme.BASIC + " " + Base64.getEncoder().encodeToString(((user + ":" + pass).getBytes()))+"1";
		checkBasicException(auth.toCharArray());		
	}	

	@Test
	public void testCredsBasic() throws Exception {
		String user = "U1-" + UUID.randomUUID().toString();
		String password = "P1-" + UUID.randomUUID().toString();
		
		// no auth
		URL url = new URL("http://127.0.0.1/index.cgi");
		checkBasicCreds(url, user, password, "", "", false, user, password); 
		url = new URL("https://127.0.0.1/index.cgi");
		checkBasicCreds(url, user, password, "", "", false, user, password); 
		url = new URL("file:///tmp/some.where");
		checkBasicCreds(url, user, password, "", "", true, null, null); 

		// user, password and auth
		String user2 = "U2-" + UUID.randomUUID().toString();
		String password2 = "P2-" + UUID.randomUUID().toString();
		String b64 = StandardAuthScheme.BASIC + " " 
				+ Base64.getEncoder().encodeToString((user2+":"+password2).getBytes());
		url = new URL("http://127.0.0.1/index.cgi");
		checkBasicCreds(url, user, password, "", b64, false, user2, password2); 
		url = new URL("https://127.0.0.1/index.cgi");
		checkBasicCreds(url, user, password, "", b64, false, user2, password2); 
		url = new URL("file:///tmp/some.where");
		checkBasicCreds(url, user, password, "", b64, true, null, null); 

		// only auth
		url = new URL("http://127.0.0.1/index.cgi");
		checkBasicCreds(url, null, null, "", b64, false, user2, password2); 
		url = new URL("https://127.0.0.1/index.cgi");
		checkBasicCreds(url, null, null, "", b64, false, user2, password2); 
		url = new URL("file:///tmp/some.where");
		checkBasicCreds(url, null, null, "", b64, true, null, null); 
	}
	
	@Test
	public void testCredsBasicException() throws Exception {
		// no password
		URL url = new URL("https://127.0.0.1/index.cgi");
		String pfx = "U-";
		checkException(url, pfx+UUID.randomUUID().toString(), null, null, "no password", pfx);
		checkException(url, null, null, UUID.randomUUID().toString(),
				"supported", StandardAuthScheme.BASIC, StandardAuthScheme.BEARER);
	}


	///////////////////////////////////////////////////
	// test bearer auth methods
	///////////////////////////////////////////////////

	@Test
	public void testGetBearerCredentials() throws Exception {
		String token = "token-" + UUID.randomUUID();
		String auth = StandardAuthScheme.BEARER + " " + token;

		Credentials credentials = Downloader.getBearerCredentialsFromAuthHeader(auth.toCharArray());
		assertNotNull(credentials);
		assertTrue(credentials instanceof BearerToken);
		assertEquals(token, ((BearerToken) credentials).getToken());

		checkBearerException(null);
		checkBearerException(new char[0]);
		auth = UUID.randomUUID().toString();
		checkBearerException(auth.toCharArray());
		auth = StandardAuthScheme.BEARER + UUID.randomUUID().toString();
		checkBearerException(auth.toCharArray());		
		auth = StandardAuthScheme.BEARER + " ";
		checkBearerException(auth.toCharArray());		
	}
	
	@Test
	public void testCredsTokenAuth() throws Exception {
		String user = "U1-" + UUID.randomUUID().toString();
		String password = "P1-" + UUID.randomUUID().toString();
		String token = "token-" + UUID.randomUUID();
		String auth = StandardAuthScheme.BEARER + " " + token;
		
		// with user / password
		URL url = new URL("http://127.0.0.1/index.cgi");
		checkTokenCreds(url, user, password, "", auth, 
				false, token); 
		url = new URL("https://127.0.0.1/index.cgi");
		checkTokenCreds(url, user, password, "", auth, 
				false, token); 
		url = new URL("file:///tmp/some.where");
		checkTokenCreds(url, user, password, "", auth, 
				true, null); 
		
		// without user / password
		url = new URL("http://127.0.0.1/index.cgi");
		checkTokenCreds(url, null, null, "", auth, 
				false, token); 
		url = new URL("https://127.0.0.1/index.cgi");
		checkTokenCreds(url, null, null, "", auth, 
				false, token); 
		url = new URL("file:///tmp/some.where");
		checkTokenCreds(url, null, null, "", auth, 
				true, null); 
	}

	
	@Test
	public void testCredsToken() throws Exception {
		String token = "token-" + UUID.randomUUID();
		URL url;
		
		// without user / password
		url = new URL("http://127.0.0.1/index.cgi");
		checkTokenCreds(url, null, null, token, "", 
				false, token); 
		url = new URL("https://127.0.0.1/index.cgi");
		checkTokenCreds(url, null, null, token, "", 
				false, token); 
		url = new URL("file:///tmp/some.where");
		checkTokenCreds(url, null, null, token, "", 
				true, null); 
	}

	@Test
	public void testCredsTokenException() throws Exception {
		String user = "U1-" + UUID.randomUUID().toString();
		String password = "P1-" + UUID.randomUUID().toString();
		String auth = StandardAuthScheme.BEARER + " ";
		URL url = new URL("https://127.0.0.1/index.cgi");
		checkException(url, null, null, null, auth, "empty bearer token");		
		checkException(url, null, null, null, StandardAuthScheme.BEARER, "should start with");		
		String token = "token-" + UUID.randomUUID().toString();
		checkException(url, user, password, token, "", "username", "token", "provided");
	}

	
	

	///////////////////////////////////////////////////
	// private test methods
	///////////////////////////////////////////////////

	private void checkException(URL url, String user, String password, String token,
			String auth, String ... messages) throws Exception {
        BasicCredentialsProvider localCredentials = new BasicCredentialsProvider();
        if(password == null) password = "";
        if(auth == null) auth = "";
        if(token == null) token = "";
        try {
            Downloader.addCredentials(localCredentials, url.toString(), 
            		url, user, password.toCharArray(),
            		token.toCharArray(), auth.toCharArray());
            throw new Exception("should have thrown an InvalidSettingException");
        } catch(InvalidSettingException ok) {
			assertNotNull(ok);
			if(messages==null || messages.length == 0)
				return;
			assertNotNull(ok.getMessage());
			for(String message : messages) {
				assertTrue(ok.getMessage().toLowerCase().contains(message.toLowerCase()));
			}
        }		
	}




	private void checkTokenCreds(URL url, String user, String password, String token, String auth, 
			boolean credIsNull, String expectedToken) throws Exception {
        BasicCredentialsProvider localCredentials = new BasicCredentialsProvider();
        if(password == null) password = "";
        if(auth == null) auth = "";
        if(token == null) token = "";
        Downloader.addCredentials(localCredentials, url.toString(), 
        		url, user, password.toCharArray(),
        		token.toCharArray(), auth.toCharArray());
		AuthScope scope = getScope(url);
		Credentials creds = localCredentials.getCredentials(scope, null);
		if(credIsNull) {
			assertNull(creds);
			return;
		}
		assertTrue(creds instanceof BearerToken);
		BearerToken bearer = (BearerToken) creds;
		assertEquals(expectedToken, bearer.getToken());
	}

	
	private void checkBasicCreds(URL url, String user, String password, 
			String token, String auth, 
			boolean credIsNull, String expectedUser, String expectedPassword) throws Exception {
        final BasicCredentialsProvider localCredentials = new BasicCredentialsProvider();
        if(password == null) password = "";
        if(token == null) token = "";
        Downloader.addCredentials(localCredentials, url.toString(), 
        		url, user, password.toCharArray(),
        		token.toCharArray(), auth.toCharArray());
        
		AuthScope scope = getScope(url);
		Credentials creds = localCredentials.getCredentials(scope, null);
		if(credIsNull) {
			assertNull(creds);
			return;
		}
		assertTrue(creds instanceof UsernamePasswordCredentials);
		UsernamePasswordCredentials basicCreds = (UsernamePasswordCredentials) creds;
		assertEquals(expectedUser, basicCreds.getUserName());
		assertEquals(expectedPassword, new String(basicCreds.getUserPassword()));
	}

	private AuthScope getScope(URL parsedURL) {
    	String theProtocol = parsedURL.getProtocol();
        String theHost = parsedURL.getHost();
        int thePort = parsedURL.getPort();
		return new AuthScope(theProtocol, theHost, thePort, null, null);
	}


	private void checkBasicException(char[] auth) throws Exception {
	      try {
	        Downloader.getBasicCredentialsFromAuthHeader(auth);
	        throw new Exception("should have thrown an InvalidSettingException");
	    } catch(InvalidSettingException ok) {
	    	assertNotNull(ok);
			assertNotNull(ok.getMessage());
	   }
	}

	private void checkBearerException(char[] auth) throws Exception {
       try {
            Downloader.getBearerCredentialsFromAuthHeader(auth);
            throw new Exception("should have thrown an InvalidSettingException");
        } catch(InvalidSettingException ok) {
			assertNotNull(ok);
			assertNotNull(ok.getMessage());
        }
	}

}
