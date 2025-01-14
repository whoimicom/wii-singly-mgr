package com.whoimi.config.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import com.whoimi.utils.WiiUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * @author whoimi
 */
@Component
public class AccessDeniedWiiImpl implements AccessDeniedHandler {
    private static final Logger logger = LoggerFactory.getLogger(AccessDeniedWiiImpl.class);
    private final ObjectMapper mapper = new ObjectMapper();
    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException {
        logger.info("");
        if (WiiUtils.isAjaxRequest(request)) {
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.getWriter().write(this.mapper.writeValueAsString(new ResponseEntity<Object>("AccessDenied", HttpStatus.UNAUTHORIZED)));
        } else {
            redirectStrategy.sendRedirect(request, response, "/access/403");
        }
    }
}