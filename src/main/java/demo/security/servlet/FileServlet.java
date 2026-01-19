package demo.security.servlet;

import demo.security.util.LoggingUtil;
import demo.security.util.Utils;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@WebServlet("/files")
public class FileServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String data = request.getParameter("data");
        
        // Log file access attempt before deletion
        if (data != null && !data.isEmpty()) {
            LoggingUtil.logFileAccess(data, "DELETE", request);
        } else {
            LoggingUtil.logSecurityWarning("File deletion attempted with empty or null filename", request);
        }
        
        try {
            Utils.deleteFile(data);
        } catch (IOException e) {
            LoggingUtil.logSecurityError("Error deleting file: " + data, e, request);
            throw e;
        }
    }
}
