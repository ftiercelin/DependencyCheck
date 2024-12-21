package org.owasp.dependencycheck.utils;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.net.URL;
import java.util.Base64;
import java.util.UUID;

import org.apache.hc.core5.http.Method;
import org.apache.hc.core5.http.message.BasicClassicHttpRequest;
import org.apache.hc.client5.http.auth.BearerToken;
import org.apache.hc.client5.http.auth.Credentials;
import org.apache.hc.client5.http.auth.StandardAuthScheme;
import org.apache.hc.client5.http.auth.UsernamePasswordCredentials;
import  org.apache.hc.core5.http.Header;

import org.junit.Test;

public class PreemptiveHttpRequestTest {
	@Test
	public void testAuthHeader() throws Exception {
		URL url = new URL("https://github.com/about");
		Credentials creds;
		BasicClassicHttpRequest req;
		
		// basic auth
		String username = "U-" + UUID.randomUUID().toString();
		char[] password = ("P-" + UUID.randomUUID().toString()).toCharArray();
		creds = new UsernamePasswordCredentials(username, password);
		req = new PreemptiveHttpRequest(Method.GET, url.toURI(), creds);
		checkHeader(req, true, StandardAuthScheme.BASIC+" "+Base64.getEncoder().encodeToString((username + ":" + new String(password)).getBytes()));
		
		
		// bearer token
		String token = "T-" + UUID.randomUUID().toString();
		creds = new BearerToken(token);
		req = new PreemptiveHttpRequest(Method.GET, url.toURI(), creds);
		checkHeader(req, true, StandardAuthScheme.BEARER+" "+token);
		
		// null
		creds = null;
		req = new PreemptiveHttpRequest(Method.GET, url.toURI(), creds);
		checkHeader(req, false, UUID.randomUUID().toString());
		
	}

	private void checkHeader(BasicClassicHttpRequest req, boolean hasAuthHeader, String expected) {
		assertNotNull(req);
		boolean found = false;
		for(Header h:req.getHeaders()) {
			assertNotNull(h);
			if(h.getName().equalsIgnoreCase("Authorization")) {
				assertTrue(hasAuthHeader);
				found = true;
				assertNotNull(h.getValue());
				assertEquals(expected, h.getValue());
			}
		}
		assert (!hasAuthHeader || found);
	}
}
