package org.pgsg.gateway.auth;

public interface AuthProvider {

	boolean verifyToken(String accessToken);
}
