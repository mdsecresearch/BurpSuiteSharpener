// Released under AGPL see LICENSE for more information
// Developed by Soroush Dalili (@irsdl)

package com.irsdl.generic;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

// This is a basic HTTP Message Helper which can get certain values by having raw HTTP message or the headers
// ToDo -> write tests for these functions -> some of them have been coded without any testing so they might be buggy!
// ToDo -> add support of LWSP when finding header values - It currently does not support LWSP anywhere
public class HTTPMessageHelper {

    //private static String LWSP_Regex= "(([\\r\\n]|\\r\\n)[ \\t]+|[ \\t])*"; // https://tools.ietf.org/html/rfc5234

    // Reads the Content-Type value from the header - reads the value before ";", "," or space
    public static String findHeaderContentType(String strHeader) {
        String contentType = "";
        if (!strHeader.equals("")) {
            Pattern my_pattern = Pattern.compile("(?im)^content-type:[ \\t]*([^;,\\s]+)");
            Matcher m = my_pattern.matcher(strHeader);
            if (m.find()) {
                contentType = m.group(1);
            }
        }
        return contentType;
    }

    // Reads the Content-Type charset value from the header - no LWSP support yet! no support for double quotes around charset value either!
    public static String findCharsetFromHeader(String strHeader, boolean trimSpaces) {
        String charset = "";
        if (!strHeader.equals("")) {
            Pattern my_pattern = Pattern.compile("(?im)^content-type:.*?[ \\t;,]+charset=[ \\t]*([\"]([^\"]+)[\"]|([^;\\s,]+))");
            Matcher m = my_pattern.matcher(strHeader);
            if (m.find()) {
                charset = m.group(1);
                charset = charset.replace("\"", "");
                if (trimSpaces)
                    charset = charset.trim();
            }
        }
        return charset;
    }

    // Reads the Content-Type boundary value from the header - no LWSP support yet!
    public static String findBoundaryFromHeader(String strHeader, boolean trimSpaces) {
        String boundary = "";
        if (!strHeader.equals("")) {
            Pattern my_pattern = Pattern.compile("(?im)^content-type:.*?[ \\t;,]+boundary=[ \\t]*([\"]([^\"]+)[\"]|([^\\s,]+))");
            Matcher m = my_pattern.matcher(strHeader);
            if (m.find()) {
                boundary = m.group(1);
                boundary = boundary.replace("\"", "");
                if (trimSpaces)
                    boundary = boundary.trim();
            }
        }
        return boundary;
    }

    // Makes a content-type header using provided parameters
    // Obviously the ";" delimiter can be changed by comma in certain cases but that's not for discussion here!
    public static String createContentTypeHeader(String cType, String charset, String boundary, boolean trimSpaces) {
        String contentType = "";
        if (trimSpaces) {
            charset = charset.trim();
            boundary = boundary.trim();
        }

        if (charset.contains(" "))
            charset = "\"" + charset + "\"";
        if (boundary.contains(" "))
            boundary = "\"" + boundary + "\"";

        contentType = cType + "; charset=" + charset;

        if (!boundary.isEmpty()) {
            contentType = cType + "; boundary=" + boundary + " ; charset=" + charset;
            // contentType = cType + "; charset=" + charset + ", boundary="+boundary; // another format
        }

        return contentType;
    }

    // Reads the Content-Type value from the header - reads the value before ";", "," or space
    public static String findHeaderContentType(List<String> headers) {
        String contentType = "";
        for (String strHeader : headers) {
            if (!strHeader.equals("")) {
                Pattern my_pattern = Pattern.compile("(?im)^content-type:[ \\t]*([^;,\\s]+)");
                Matcher m = my_pattern.matcher(strHeader);
                if (m.find()) {
                    contentType = m.group(1);
                    break;
                }
            }
        }
        return contentType;
    }


    // Splits header and body of a request or response
    public static List<byte[]> getHeaderAndBody(byte[] fullMessage, int bodyOffset) {
        List<byte[]> result = new ArrayList<>();
        if (fullMessage.length >= bodyOffset) {
            result.add(Arrays.copyOfRange(fullMessage, 0, bodyOffset));
            result.add(Arrays.copyOfRange(fullMessage, bodyOffset, fullMessage.length));
        } else {
            result.add(fullMessage);
            result.add(new byte[]{});
        }

        return result;
    }

    // Splits header and body of a request or response
    public static String[] getHeaderAndBody(byte[] fullMessage, String encoding) throws UnsupportedEncodingException {
        return getHeaderAndBody(new String(fullMessage, encoding));
    }

    // Splits header and body of a request or response
    public static String[] getHeaderAndBody(String fullMessage) {
        String[] result = {"", ""};
        if (fullMessage != null) {
            // splitting the message to retrieve the header and the body
            if (fullMessage.contains("\r\n\r\n") || fullMessage.contains("\n\n"))
                result = fullMessage.split("\\r?\\n\\r?\\n|\\r\\n?\\r\\n?", 2);
        }
        return result;
    }

    // Splits header and body of a request or response
    public static List<String> getHeadersListFromFullRequest(byte[] fullMessage) {
        return getHeadersListFromFullRequest(new String(fullMessage, StandardCharsets.ISO_8859_1));
    }

    // Splits header and body of a request or response
    public static List<String> getHeadersListFromHeader(byte[] headerMessage) {
        return new ArrayList<>(Arrays.asList(new String(headerMessage, StandardCharsets.ISO_8859_1).split("\r?\n")));
    }

    // Splits header and body of a request or response
    public static List<String> getHeadersListFromFullRequest(String fullMessage) {
        String[] result = getHeaderAndBody(fullMessage);
        return new ArrayList<>(Arrays.asList(result[0].split("\r?\n")));
    }

    // Get the body of a raw http request
    public static String getBody(String fullMessage) {
        return getHeaderAndBody(fullMessage)[1];
    }

    // Add a new header to a full raw request
    public static String addSingleHeader(String fullMessage, String newSingleHeader) {
        List<String> headers = getHeadersListFromFullRequest(fullMessage);
        headers.add(newSingleHeader);
        return replaceAllHeaders(fullMessage, headers);
    }

    // Replace the header of a full raw request with a new header list
    public static String replaceAllHeaders(String fullMessage, List<String> newHeader) {
        return replaceAllHeaders(fullMessage, String.join("\r\n", newHeader));
    }

    // Replace the header of a full raw request with a new header list
    public static String replaceAllHeaders(String fullMessage, String newHeader) {
        var headerAndBody = getHeaderAndBody(fullMessage);
        return newHeader + "\r\n\r\n" + headerAndBody[1];
    }


    public static List<List<String>> getQueryString(String fullMessage) {
        return getQueryString(fullMessage, "", "");
    }

    public static List<List<String>> getQueryString(String fullMessage, String delimiter_QS_param) {
        return getQueryString(fullMessage, "", delimiter_QS_param);
    }

    // gets url parameters because burp can't handle special cases such as when we have jsessionid after semicolon
    public static List<List<String>> getQueryString(String reqMessage, String delimiter_QS, String delimiter_QS_param) {
        if (delimiter_QS.isEmpty()) delimiter_QS = "?";
        if (delimiter_QS_param.isEmpty()) delimiter_QS = "&";
        // final object with qs name and its value
        List<List<String>> qs_list = new ArrayList<List<String>>();

        // we assume that we are dealing with one HTTP message (not multiple in a pipeline)
        String firstLine = reqMessage.split("\\r?\\n|\\r\\n?", 2)[0];

        // we assume that we are dealing with a standard HTTP message in which there is a space after the last parameter value
        String QS = "";

        Pattern pattern = Pattern.compile(Encoding.unicodeEscape(delimiter_QS, true, false) + "([^ \\s]+)");
        Matcher matcher = pattern.matcher(firstLine);
        if (matcher.find()) {
            QS = matcher.group(1);
        }

        if (!QS.isEmpty()) {
            String[] keyValues = QS.split(Encoding.unicodeEscape(delimiter_QS_param, true, false));
            for (String keyValue : keyValues) {
                List<String> keyValueList = new ArrayList<String>();
                String key = keyValue;
                String value = "";
                if (keyValue.contains("=")) {
                    key = keyValue.split("=", 2)[0];
                    value = keyValue.split("=", 2)[1];
                }
                keyValueList.add(key);
                keyValueList.add(value);
                qs_list.add(keyValueList);
            }
        }
        return qs_list;
    }


    public static List<List<String>> getURLEncodedBodyParams(String strMessage, boolean isBodyOnly) {
        return getURLEncodedBodyParams(strMessage, isBodyOnly, "");
    }

    // gets URLEncoded POST parameters - it can use different delimiters than &
    public static List<List<String>> getURLEncodedBodyParams(String strMessage, boolean isBodyOnly, String delimiter_urlencoded_body_param) {
        if (delimiter_urlencoded_body_param.isEmpty()) delimiter_urlencoded_body_param = "&";
        if (!isBodyOnly) {
            strMessage = getHeaderAndBody(strMessage)[1];
        }
        // final object with param name and its value
        List<List<String>> param_list = new ArrayList<List<String>>();
        String[] keyValues = strMessage.split(Encoding.unicodeEscape(delimiter_urlencoded_body_param, true, false));
        for (String keyValue : keyValues) {
            List<String> keyValueList = new ArrayList<String>();
            String key = keyValue;
            String value = "";
            if (keyValue.contains("=")) {
                key = keyValue.split("=", 2)[0];
                value = keyValue.split("=", 2)[1];
            }
            keyValueList.add(key);
            keyValueList.add(value);
            param_list.add(keyValueList);
        }
        return param_list;
    }


    public static String replaceQueryString(String reqMessage, String newQS) {
        return replaceQueryString(reqMessage, newQS, "");
    }

    // replaces url parameters or adds it if empty in a request
    public static String replaceQueryString(String reqMessage, String newQS, String delimiter_QS) {
        String finalMessage;
        if (delimiter_QS.isEmpty()) delimiter_QS = "?";
        // we assume that we are dealing with one HTTP message (not multiple in a pipeline)
        String[] splittedRequest = reqMessage.split("\\r?\\n|\\r\\n?", 2);
        String firstLine = splittedRequest[0];
        firstLine = firstLine.trim(); // we don't have spaces before or after the first line if it is standard!

        String QS_pattern = Encoding.unicodeEscape(delimiter_QS, true, false) + "[^ \\s]+";
        Pattern pattern = Pattern.compile(QS_pattern);
        Matcher matcher = pattern.matcher(firstLine);
        if (matcher.find()) {
            // replacing existing QS
            firstLine = matcher.replaceAll(delimiter_QS + newQS);
        } else {
            // adding QS to the request
            String HTTP_version_pattern = "([ ]+HTTP/[^\\s]+)";
            pattern = Pattern.compile(HTTP_version_pattern);
            matcher = pattern.matcher(firstLine);
            if (matcher.find()) {
                firstLine = matcher.replaceAll(delimiter_QS + newQS + "$1");
            } else {
                // HTTP v0.9?!
                firstLine += delimiter_QS + newQS;
            }

        }
        finalMessage = firstLine + "\r\n" + splittedRequest[1];
        return finalMessage;
    }

    // get values of a header even when it is duplicated
    public static ArrayList<String> getAllHeaderValuesByName(List<String> headers, String headerName) {
        ArrayList<String> result = new ArrayList<String>();
        headerName = headerName.toLowerCase();
        for (String item : headers) {
            if (item.indexOf(":") >= 0) {
                String[] headerItem = item.split(":", 2);
                String headerNameLC = headerItem[0].toLowerCase();
                if (headerNameLC.equals(headerName)) {
                    // We have a match
                    result.add(headerItem[1].trim());
                }
            }
        }
        return result;
    }

    // get the first value of a header
    public static String getFirstHeaderValueByNameFromHeaders(List<String> headers, String headerName, boolean isCaseSensitive) {
        String result = "";
        if(!isCaseSensitive)
            headerName = headerName.toLowerCase();

        for (String item : headers) {
            if (item.indexOf(":") >= 0) {
                String[] headerItem = item.split(":", 2);
                String headerNameLC = headerItem[0].toLowerCase();
                if (headerNameLC.equals(headerName)) {
                    // We have a match
                    result = headerItem[1].trim();
                    break;
                }
            }
        }
        return result;
    }

    public static ArrayList<String> removeHeadersByName(List<String> headers, String headerName) {
        ArrayList<String> result = new ArrayList<String>();
        headerName = headerName.toLowerCase();
        for (String item : headers) {
            if (item.indexOf(":") >= 0) {
                String[] headerItem = item.split(":", 2);
                String headerNameLC = headerItem[0].toLowerCase();
                if (!headerNameLC.equals(headerName)) {
                    // Header name is different so we keep it!
                    result.add(item);
                }
            } else {
                result.add(item);
            }
        }
        return result;
    }

    // get values of a cookie even when it is duplicated
    public static ArrayList<String> getAllCookieValuesByName(String cookieHeaderValue, String targetCookieName, boolean isCaseSensitive, boolean isRequest) {
        ArrayList<String> result = new ArrayList<String>();
        if (!isCaseSensitive) {
            targetCookieName = targetCookieName.toLowerCase();
        }

        var cookieNameValues = cookieHeaderValue.split(";");

        if (!isRequest) {
            cookieNameValues = new String[]{cookieNameValues[0]};
        }

        for (var cookieNameValue : cookieNameValues) {
            cookieNameValue = cookieNameValue.trim();
            var cookieNameValueArray = cookieNameValue.split("=", 2);
            var cookieName = cookieNameValueArray[0].trim();
            var cookieValue = "";
            if (cookieNameValueArray.length == 2) {
                cookieValue = cookieNameValueArray[1].trim();
            }

            if (!isCaseSensitive) {
                cookieName = cookieName.toLowerCase();
            }

            if (targetCookieName.equals(cookieName)) {
                // we have a match
                result.add(cookieValue);
            }
        }
        return result;
    }

    // get the first value of a cookie
    public static String getFirstCookieValueByName(String cookieHeaderValue, String targetCookieName, boolean isCaseSensitive, boolean isRequest) {
        String result = "";

        if (!isCaseSensitive) {
            targetCookieName = targetCookieName.toLowerCase();
        }

        var cookieNameValues = cookieHeaderValue.split(";");

        if (!isRequest) {
            cookieNameValues = new String[]{cookieNameValues[0]};
        }

        for (var cookieNameValue : cookieNameValues) {
            cookieNameValue = cookieNameValue.trim();
            var cookieNameValueArray = cookieNameValue.split("=", 2);
            var cookieName = cookieNameValueArray[0].trim();
            var cookieValue = "";
            if (cookieNameValueArray.length == 2) {
                cookieValue = cookieNameValueArray[1].trim();
            }

            if (!isCaseSensitive) {
                cookieName = cookieName.toLowerCase();
            }

            if (targetCookieName.equals(cookieName)) {
                // we have a match
                result = cookieValue;
                break;
            }
        }
        return result;
    }

    // get values of a cookie even when it is duplicated
    public static ArrayList<String> getAllCookieValuesByNameFromHeaders(List<String> headers, String targetCookieName, boolean isCaseSensitive, boolean isRequest) {
        ArrayList<String> result = new ArrayList<String>();
        String headerName = "Cookie";
        if (!isRequest) {
            headerName = "Set-cookie";
        }

        var allCookieHeaders = getAllHeaderValuesByName(headers, headerName);
        for (var cookieHeader : allCookieHeaders) {
            var currentResults = getAllCookieValuesByName(cookieHeader, targetCookieName, isCaseSensitive, isRequest);
            if (currentResults.size() > 0) {
                result.addAll(currentResults);
            }
        }

        return result;
    }

    // get the first value of a cookie
    public static String getFirstCookieValueByNameFromHeaders(List<String> headers, String targetCookieName, boolean isCaseSensitive, boolean isRequest) {
        String result = "";
        String headerName = "Cookie";
        if (!isRequest) {
            headerName = "Set-cookie";
        }

        var cookieHeader = getFirstHeaderValueByNameFromHeaders(headers, headerName, false);
        result = getFirstCookieValueByName(cookieHeader, targetCookieName, isCaseSensitive, isRequest);

        return result;
    }

    // replace or add a cookie value with the new value
    public static String replaceOrAddCookieValuesInCookieString(String cookieHeaderValue, String targetCookieName, String newCookieValue, boolean isCaseSensitive) {
        String result;

        var flags = Pattern.CASE_INSENSITIVE | Pattern.MULTILINE;
        if (isCaseSensitive) {
            flags = Pattern.MULTILINE;
        }

        String cookie_pattern_string = Pattern.quote(targetCookieName) + "\\s*=\\s*[^;\\r\\n]+";

        Pattern cookie_pattern = Pattern.compile(cookie_pattern_string, flags);
        Matcher m = cookie_pattern.matcher(cookieHeaderValue);
        if (m.find()) {
            // replacing
            result = m.replaceAll(targetCookieName + "=" + newCookieValue);
        } else {
            // adding
            result = cookieHeaderValue + "; " + targetCookieName + "=" + newCookieValue + ";";
        }
        return result;
    }

    // replace or add a cookie value with the new value
    public static List<String> replaceOrAddCookieValuesInHeaderList(List<String> headers, String targetCookieName, String newCookieValue, boolean isCaseSensitive, boolean isRequest) {
        List<String> result = new ArrayList<String>();

        String headerName = "cookie";
        if (!isRequest) {
            headerName = "set-cookie";
        }

        var currentCookieHeaders = getAllHeaderValuesByName(headers, headerName);
        var currentCookiesWithName = getAllCookieValuesByNameFromHeaders(headers, targetCookieName, isCaseSensitive, isRequest);

        if (currentCookieHeaders.size() <= 0 || (!isRequest && currentCookiesWithName.size() <= 0)) {
            result.addAll(headers);
            result.add(headerName + ": " + targetCookieName + "=" + newCookieValue + ";");
        } else {
            if (currentCookiesWithName.size() <= 0) {
                // this is a request but has a cookie header
                result = removeHeadersByName(headers, headerName);
                var newCookieStr = replaceOrAddCookieValuesInCookieString(currentCookieHeaders.get(0), targetCookieName, newCookieValue, isCaseSensitive);
                result.add(headerName + ": " + newCookieStr);
            } else {
                // this is a request or response - we have at least a match...
                int counter = 0;
                boolean matchFound = false;
                for (String item : headers) {
                    if (item.indexOf(":") >= 0 && counter != 0) {
                        String[] headerItem = item.split(":", 2);
                        String headerNameForComp = headerItem[0];
                        if (!isCaseSensitive)
                            headerNameForComp = headerNameForComp.toLowerCase();
                        if (headerNameForComp.equals(headerName)) {
                            // We have a cookie header, now we need to see whether it has the targetedCookie inside it
                            var cookieHeaderValue = headerItem[1].trim();
                            if (getAllCookieValuesByName(cookieHeaderValue, targetCookieName, isCaseSensitive, isRequest).size() > 0) {
                                // this is the cookie we are after
                                headerItem[1] = replaceOrAddCookieValuesInCookieString(cookieHeaderValue, targetCookieName, newCookieValue, isCaseSensitive);
                            }
                        }
                        result.add(headerItem[0] + ": " + headerItem[1].trim());
                    } else {
                        result.add(item);
                    }
                    counter++;
                }
            }

        }

        return result;
    }

    // replace or add a cookie value with the new value - this uses a RegEx which might be a faster approach...
    public static String replaceOrAddCookieValuesInHeaderString(String strHeader, String targetCookieName, String newCookieValue, boolean isCaseSensitive, boolean isRequest) {
        String result = "";

        String headerName = "Cookie";
        if (!isRequest) {
            headerName = "Set-Cookie";
        }

        var flags = Pattern.CASE_INSENSITIVE | Pattern.MULTILINE;
        if (isCaseSensitive) {
            flags = Pattern.MULTILINE;
        }

        String cookie_pattern_string = "^(" + Pattern.quote(headerName) + "\\s*:\\s*.*" + Pattern.quote(targetCookieName) + "\\s*=\\s*)[^;\\r\\n]+(.*)$";

        Pattern cookie_pattern = Pattern.compile(cookie_pattern_string, flags);
        Matcher m = cookie_pattern.matcher(strHeader);
        if (m.find()) {
            // replacing
            result = m.replaceAll("$1" + targetCookieName + "=" + newCookieValue + "$2");
        } else {
            // adding
            result = addHeader(strHeader, headerName, newCookieValue + "=" + newCookieValue + ";");
        }

        return result;
    }

    // replace or add a header value with the new value
    public static List<String> replaceOrAddHeaderValuesInHeaderList(List<String> headers, String headerName, String newHeaderValue, boolean isCaseSensitive) {
        List<String> result = new ArrayList<String>();
        if (!isCaseSensitive)
            headerName = headerName.toLowerCase();
        int counter = 0;
        boolean matchFound = false;
        for (String item : headers) {
            if (item.indexOf(":") >= 0 && counter != 0) {
                String[] headerItem = item.split(":", 2);
                String headerNameForComp = headerItem[0];
                if (!isCaseSensitive)
                    headerNameForComp = headerNameForComp.toLowerCase();
                if (headerNameForComp.equals(headerName)) {
                    // We have a match
                    headerItem[1] = newHeaderValue;
                    matchFound = true;
                }
                result.add(headerItem[0] + ": " + headerItem[1].trim());
            } else {
                result.add(item);
            }
            counter++;
        }

        if (!matchFound) {
            result.add(headerName + ": " + newHeaderValue);
        }

        return result;
    }

    // replace or add a header value with the new value - this uses a RegEx which might be a faster approach...
    public static String replaceOrAddHeaderValuesInHeaderString(String strHeader, String headerName, String newHeaderValue, boolean isCaseSensitive) {
        String result = "";
        String header_pattern_string = "(?im)^(" + Pattern.quote(headerName) + ":).*$";
        if (isCaseSensitive) {
            header_pattern_string = "(?m)^(" + Pattern.quote(headerName) + ":).*$";
        }

        Pattern header_pattern = Pattern.compile(header_pattern_string);
        Matcher m = header_pattern.matcher(strHeader);
        if (m.find()) {
            // replacing
            result = m.replaceAll("$1 " + newHeaderValue);
        } else {
            // adding
            result = addHeader(strHeader, headerName, newHeaderValue);
        }
        return result;
    }


    // add a new header and its value - this is vulnerable to CRLF but that's intentional
    public static String addHeader(String strHeader, String newHeaderName, String newHeaderValue) {
        return addHeader(strHeader, newHeaderName + ": " + newHeaderValue);
    }

    // add a new header - this is vulnerable to CRLF but that's intentional
    public static String addHeader(String strHeader, String newHeader) {
        String result = "";
        // adding the new header to the second line after the HTTP version!
        result = strHeader.replaceFirst("([\\r\\n]+)", "$1" + newHeader + "$1");
        return result;
    }

    // replace a header verb with a new verb
    public static String replaceHeaderVerb(String strHeader, String newVerb) {
        String result = "";
        result = strHeader.replaceFirst("^[^ \\t]+", newVerb);
        return result;
    }

}
