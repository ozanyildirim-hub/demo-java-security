package demo.security.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import javax.servlet.http.HttpServletRequest;

/**
 * Utility class for logging security-related events.
 * Provides methods to log failed login attempts, SQL query executions, and file access.
 */
public class LoggingUtil {
    
    private static final Logger securityLogger = LoggerFactory.getLogger("SECURITY");
    private static final Logger sqlLogger = LoggerFactory.getLogger("SQL");
    private static final Logger fileLogger = LoggerFactory.getLogger("FILE_ACCESS");
    
    // Constants for MDC keys and event types
    private static final String MDC_KEY_USERNAME = "username";
    private static final String MDC_KEY_IP = "ip";
    private static final String MDC_KEY_EVENT = "event";
    private static final String MDC_KEY_FILENAME = "filename";
    private static final String MDC_KEY_OPERATION = "operation";
    private static final String UNKNOWN_VALUE = "unknown";
    private static final String EVENT_FAILED_LOGIN = "FAILED_LOGIN";
    private static final String EVENT_SUCCESSFUL_LOGIN = "SUCCESSFUL_LOGIN";
    private static final String EVENT_SQL_QUERY = "SQL_QUERY";
    private static final String EVENT_FILE_ACCESS = "FILE_ACCESS";
    private static final String EVENT_SECURITY_WARNING = "SECURITY_WARNING";
    private static final String EVENT_SECURITY_ERROR = "SECURITY_ERROR";
    
    // Private constructor to prevent instantiation
    private LoggingUtil() {
        throw new UnsupportedOperationException("Utility class cannot be instantiated");
    }
    
    /**
     * Logs a failed login attempt.
     * 
     * @param username The username that attempted to login
     * @param request The HTTP request (for IP address extraction)
     * @param reason The reason for the failure
     */
    public static void logFailedLoginAttempt(String username, HttpServletRequest request, String reason) {
        String clientIp = getClientIpAddress(request);
        String safeUsername = username != null ? username : UNKNOWN_VALUE;
        MDC.put(MDC_KEY_USERNAME, safeUsername);
        MDC.put(MDC_KEY_IP, clientIp);
        MDC.put(MDC_KEY_EVENT, EVENT_FAILED_LOGIN);
        
        securityLogger.warn("Failed login attempt - Username: {}, IP: {}, Reason: {}", 
                safeUsername, clientIp, reason);
        
        MDC.clear();
    }
    
    /**
     * Logs a successful login attempt.
     * 
     * @param username The username that successfully logged in
     * @param request The HTTP request (for IP address extraction)
     */
    public static void logSuccessfulLogin(String username, HttpServletRequest request) {
        String clientIp = getClientIpAddress(request);
        MDC.put(MDC_KEY_USERNAME, username);
        MDC.put(MDC_KEY_IP, clientIp);
        MDC.put(MDC_KEY_EVENT, EVENT_SUCCESSFUL_LOGIN);
        
        securityLogger.info("Successful login - Username: {}, IP: {}", username, clientIp);
        
        MDC.clear();
    }
    
    /**
     * Logs SQL query execution.
     * 
     * @param query The SQL query being executed
     * @param request The HTTP request (for context)
     */
    public static void logSqlQuery(String query, HttpServletRequest request) {
        String clientIp = request != null ? getClientIpAddress(request) : UNKNOWN_VALUE;
        MDC.put(MDC_KEY_IP, clientIp);
        MDC.put(MDC_KEY_EVENT, EVENT_SQL_QUERY);
        
        sqlLogger.info("SQL query executed - Query: {}, IP: {}", sanitizeQuery(query), clientIp);
        
        MDC.clear();
    }
    
    /**
     * Logs SQL query execution without request context.
     * 
     * @param query The SQL query being executed
     */
    public static void logSqlQuery(String query) {
        MDC.put(MDC_KEY_EVENT, EVENT_SQL_QUERY);
        
        sqlLogger.info("SQL query executed - Query: {}", sanitizeQuery(query));
        
        MDC.clear();
    }
    
    /**
     * Logs file access operations.
     * 
     * @param fileName The name/path of the file being accessed
     * @param operation The operation being performed (e.g., "READ", "DELETE", "WRITE")
     * @param request The HTTP request (for IP address extraction)
     */
    public static void logFileAccess(String fileName, String operation, HttpServletRequest request) {
        String clientIp = getClientIpAddress(request);
        MDC.put(MDC_KEY_FILENAME, fileName);
        MDC.put(MDC_KEY_OPERATION, operation);
        MDC.put(MDC_KEY_IP, clientIp);
        MDC.put(MDC_KEY_EVENT, EVENT_FILE_ACCESS);
        
        fileLogger.info("File access - File: {}, Operation: {}, IP: {}", 
                sanitizeFileName(fileName), operation, clientIp);
        
        MDC.clear();
    }
    
    /**
     * Logs file access operations without request context.
     * 
     * @param fileName The name/path of the file being accessed
     * @param operation The operation being performed (e.g., "READ", "DELETE", "WRITE")
     */
    public static void logFileAccess(String fileName, String operation) {
        MDC.put(MDC_KEY_FILENAME, fileName);
        MDC.put(MDC_KEY_OPERATION, operation);
        MDC.put(MDC_KEY_EVENT, EVENT_FILE_ACCESS);
        
        fileLogger.info("File access - File: {}, Operation: {}", 
                sanitizeFileName(fileName), operation);
        
        MDC.clear();
    }
    
    /**
     * Logs a security warning.
     * 
     * @param message The warning message
     * @param request The HTTP request (for context)
     */
    public static void logSecurityWarning(String message, HttpServletRequest request) {
        String clientIp = request != null ? getClientIpAddress(request) : UNKNOWN_VALUE;
        MDC.put(MDC_KEY_IP, clientIp);
        MDC.put(MDC_KEY_EVENT, EVENT_SECURITY_WARNING);
        
        securityLogger.warn("Security warning - Message: {}, IP: {}", message, clientIp);
        
        MDC.clear();
    }
    
    /**
     * Logs a security error.
     * 
     * @param message The error message
     * @param exception The exception that occurred
     * @param request The HTTP request (for context)
     */
    public static void logSecurityError(String message, Exception exception, HttpServletRequest request) {
        String clientIp = request != null ? getClientIpAddress(request) : UNKNOWN_VALUE;
        MDC.put(MDC_KEY_IP, clientIp);
        MDC.put(MDC_KEY_EVENT, EVENT_SECURITY_ERROR);
        
        securityLogger.error("Security error - Message: {}, IP: {}", message, clientIp, exception);
        
        MDC.clear();
    }
    
    /**
     * Extracts the client IP address from the request.
     * 
     * @param request The HTTP request
     * @return The client IP address
     */
    private static String getClientIpAddress(HttpServletRequest request) {
        if (request == null) {
            return UNKNOWN_VALUE;
        }
        
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null || ip.isEmpty() || UNKNOWN_VALUE.equalsIgnoreCase(ip)) {
            ip = request.getHeader("X-Real-IP");
        }
        if (ip == null || ip.isEmpty() || UNKNOWN_VALUE.equalsIgnoreCase(ip)) {
            ip = request.getRemoteAddr();
        }
        
        return ip != null ? ip : UNKNOWN_VALUE;
    }
    
    /**
     * Sanitizes SQL query for logging (removes sensitive data if needed).
     * 
     * @param query The SQL query
     * @return The sanitized query
     */
    private static String sanitizeQuery(String query) {
        if (query == null) {
            return "null";
        }
        // In a production environment, you might want to remove or mask sensitive data
        // For now, we'll just truncate very long queries
        if (query.length() > 500) {
            return query.substring(0, 500) + "... [truncated]";
        }
        return query;
    }
    
    /**
     * Sanitizes file name for logging (removes path traversal attempts).
     * 
     * @param fileName The file name
     * @return The sanitized file name
     */
    private static String sanitizeFileName(String fileName) {
        if (fileName == null) {
            return "null";
        }
        // Replace path traversal attempts with a safe representation
        return fileName.replace("../", "[PATH_TRAVERSAL]/")
                      .replace("..\\", "[PATH_TRAVERSAL]\\");
    }
}
