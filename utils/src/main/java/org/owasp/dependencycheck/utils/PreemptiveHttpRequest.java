package org.owasp.dependencycheck.utils;

import java.net.URI;
import java.util.Base64;

import org.apache.hc.client5.http.auth.BearerToken;
import org.apache.hc.client5.http.auth.Credentials;
import org.apache.hc.client5.http.auth.StandardAuthScheme;
import org.apache.hc.client5.http.auth.UsernamePasswordCredentials;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.Method;
import org.apache.hc.core5.http.message.BasicClassicHttpRequest;
import org.apache.hc.core5.http.message.BasicHeader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PreemptiveHttpRequest extends BasicClassicHttpRequest {
	private static final long serialVersionUID = 3408352419400427838L;
	private static final Logger LOGGER = LoggerFactory.getLogger(PreemptiveHttpRequest.class);
	private static final String AUTH_HEADER = "Authorization";
	private static final String ADD_HEADER_MSG = "Adding header: '{}:{} xxxx' for {} {}";

    
    public PreemptiveHttpRequest(final Method method, final URI requestUri, final Credentials creds) {
        super(method, requestUri);
		Header header = getHeader(creds);
		if (header != null) {
			setHeader(header);
		}
	}
	
	protected Header getHeader(Credentials creds) {
		if (creds == null) {
			LOGGER.error("No credentials provided for {} {}", getMethod(), getRequestUri());
			return null;
		}
		if (creds instanceof UsernamePasswordCredentials) {
			UsernamePasswordCredentials upc = (UsernamePasswordCredentials) creds;
			LOGGER.trace(ADD_HEADER_MSG, AUTH_HEADER, StandardAuthScheme.BASIC,
					getMethod(), getRequestUri());
			return new BasicHeader(AUTH_HEADER, StandardAuthScheme.BASIC + " " + Base64.getEncoder().encodeToString((upc.getUserName() + ":" + new String(upc.getUserPassword())).getBytes()));
		} else if (creds instanceof BearerToken) {
			BearerToken bt = (BearerToken) creds;
			LOGGER.trace(ADD_HEADER_MSG, AUTH_HEADER, StandardAuthScheme.BEARER,
					getMethod(), getRequestUri());
			return new BasicHeader(AUTH_HEADER, StandardAuthScheme.BEARER + " " + bt.getToken());
		} 

		LOGGER.error("Unknown credentials: {} ({}) for {} {}", 
				creds.getClass().getSimpleName(),creds.getUserPrincipal(),
				getMethod(), getRequestUri());
		return null;
	}
}
