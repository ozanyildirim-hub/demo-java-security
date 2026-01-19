package demo.security.servlet;

import demo.security.util.DBUtils;
import demo.security.util.LoggingUtil;
import demo.security.util.SessionHeader;
import org.apache.commons.codec.binary.Base64;

import javax.servlet.*;
import javax.servlet.http.*;
import javax.servlet.annotation.*;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.PrintWriter;
import java.util.List;

@WebServlet("/users")
public class UserServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String user = request.getParameter("username");
        try {
            // Log SQL query execution
            LoggingUtil.logSqlQuery("SELECT userid FROM users WHERE username = '" + user + "'", request);
            
            DBUtils db = new DBUtils();
            List<String> users = db.findUsers(user);
            
            // Log failed login attempt if no users found
            if (users.isEmpty() && user != null && !user.isEmpty()) {
                LoggingUtil.logFailedLoginAttempt(user, request, "User not found");
            } else if (!users.isEmpty()) {
                // Log successful user lookup
                LoggingUtil.logSuccessfulLogin(user, request);
            }
            
            response.setContentType("text/html");
            PrintWriter out = response.getWriter();
            users.forEach((result) -> {
                        out.print("<h2>User "+result+ "</h2>");
            });
            out.close();
        } catch (Exception e) {
            LoggingUtil.logSecurityError("Error processing user request", new RuntimeException(e), request);
            throw new RuntimeException(e);
        }

    }

    private SessionHeader getSessionHeader(HttpServletRequest request) {
        String sessionAuth = request.getHeader("Session-Auth");
        if (sessionAuth != null) {
            try {
                byte[] decoded = Base64.decodeBase64(sessionAuth);
                ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(decoded));
                return (SessionHeader) in.readObject();
            } catch (Exception e) {
                return null;
            }
        }
        return null;
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        SessionHeader sessionHeader = getSessionHeader(request);
        if (sessionHeader == null) {
            LoggingUtil.logSecurityWarning("Invalid or missing session header in POST request", request);
            return;
        }
        String user = sessionHeader.getUsername();
        try {
            // Log SQL query execution
            LoggingUtil.logSqlQuery("SELECT userid FROM users WHERE username = '" + user + "'", request);
            
            DBUtils db = new DBUtils();
            List<String> users = db.findUsers(user);
            
            // Log failed login attempt if no users found
            if (users.isEmpty() && user != null && !user.isEmpty()) {
                LoggingUtil.logFailedLoginAttempt(user, request, "User not found");
            } else if (!users.isEmpty()) {
                // Log successful user lookup
                LoggingUtil.logSuccessfulLogin(user, request);
            }
            
            response.setContentType("text/html");
            PrintWriter out = response.getWriter();
            users.forEach((result) -> {
                out.print("<h2>User "+result+ "</h2>");
            });
            out.close();
        } catch (Exception e) {
            LoggingUtil.logSecurityError("Error processing user POST request", new RuntimeException(e), request);
            throw new RuntimeException(e);
        }
    }
}
