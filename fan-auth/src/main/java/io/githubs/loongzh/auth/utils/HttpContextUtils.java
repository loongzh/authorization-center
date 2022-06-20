package io.githubs.loongzh.auth.utils;

import org.springframework.http.HttpStatus;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * Http上下文工具
 *
 * @author luohq
 * @version 1.0.0
 * @date 2022-02-22 12:48
 */
public class HttpContextUtils {

    public static HttpServletRequest getRequest() {
        return ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest();
    }

    public static HttpServletResponse getResponse() {
        return ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getResponse();
    }

    public static String getSessionId() {
        return RequestContextHolder.getRequestAttributes().getSessionId();
    }

    public static HttpSession getSession(boolean create) {
        return getRequest().getSession(create);
    }

    public static HttpSession getExistSession() {
        return getRequest().getSession(false);
    }


    /**
     * 发送响应status
     *
     * @param httpStatus
     * @param response
     * @throws IOException
     */
    public static void responseStatus(HttpStatus httpStatus, HttpServletResponse response) throws IOException {
        response.setStatus(httpStatus.value());
        response.getWriter().flush();
    }

    /**
     * 发送响应text
     *
     * @param text
     * @param response
     * @throws IOException
     */
    public static void responseText(String text, HttpServletResponse response) throws IOException {
        response.setContentType("text/html;charset=UTF-8");
        response.setContentLength(text.getBytes(StandardCharsets.UTF_8).length);
        response.getWriter().write(text);
    }

    /**
     * 发送响应Json
     *
     * @param json
     * @param response
     * @throws IOException
     */
    public static void responseJson(String json, HttpServletResponse response) throws IOException {
        response.setStatus(HttpStatus.OK.value());
        response.setContentType("application/json;charset=utf-8");
        response.setContentLength(json.getBytes(StandardCharsets.UTF_8).length);
        response.getWriter().write(json);
    }

}
