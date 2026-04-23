package demo.security.util;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class SessionHeader {
    private String username;
    private String sessionId;

    @JsonCreator
    public SessionHeader(
            @JsonProperty("username") String username,
            @JsonProperty("sessionId") String sessionId) {
        this.username = username;
        this.sessionId = sessionId;
    }
    public String getUsername() { return this.username; }
    public void setUsername(String username) { this.username = username; }
    public String getSessionId() { return this.sessionId; }
    public void setSessionId(String sessionId) { this.sessionId = sessionId; }
}