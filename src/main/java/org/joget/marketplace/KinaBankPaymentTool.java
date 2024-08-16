package org.joget.marketplace;

import com.google.gson.Gson;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.DecimalFormat;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.joget.apps.app.model.AppDefinition;
import org.joget.apps.app.service.AppService;
import org.joget.apps.app.service.AppUtil;
import org.joget.apps.form.dao.FormDataDao;
import org.joget.apps.form.model.FormRow;
import org.joget.apps.form.model.FormRowSet;
import org.joget.apps.form.service.FormUtil;
import org.joget.commons.util.LogUtil;
import org.joget.marketplace.model.PluginProperties;
import org.joget.plugin.base.DefaultApplicationPlugin;
import org.joget.plugin.base.PluginWebSupport;
import org.joget.workflow.model.WorkflowAssignment;

public class KinaBankPaymentTool extends DefaultApplicationPlugin implements PluginWebSupport {

    private static final String CHARACTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String FORM_ID = "formId";
    private static final String RESPONSE_FORM_ID = "responseFormId";
    private static final String SECRET = "secret";
    private static final String USERVIEW_ID = "userviewId";
    private static final String USERVIEW_MENU_ID = "userviewMenuId";
    private static final String MERCHANT = "merchant";
    private static final String TERMINAL = "terminal";

    @Override
    public Object execute(Map properties) {

        AppService appService = (AppService) FormUtil.getApplicationContext().getBean("appService");
        String recordId;
        AppDefinition appDef = (AppDefinition) properties.get("appDef");
        String appVersion = String.valueOf(appDef.getVersion());
        String appId = appDef.getAppId();

        WorkflowAssignment wfAssignment = (WorkflowAssignment) properties.get("workflowAssignment");

        if (wfAssignment != null) {
            recordId = appService.getOriginProcessId(wfAssignment.getProcessId());
        } else {
            recordId = (String) properties.get("recordId");
        }

        if (recordId != null && !recordId.isEmpty()) {

            String secretKey = AppUtil.processHashVariable("#appVariable." + SECRET + "#", null, null, null);
            String paymentFormId = AppUtil.processHashVariable("#appVariable." + FORM_ID + "#", null, null, null);
            String responseFormId = AppUtil.processHashVariable("#appVariable." + RESPONSE_FORM_ID + "#", null, null, null);
            String redirectUserviewMenu = AppUtil.processHashVariable("#appVariable." + USERVIEW_ID + "#", null, null, null);
            String redirectUserviewMenuFormID = AppUtil.processHashVariable("#appVariable." + USERVIEW_MENU_ID + "#", null, null, null);

            // load the data
            FormRowSet frs = appService.loadFormData(appId, appVersion, paymentFormId, recordId);
            FormRow formRow = frs.get(0);

            // get all the values and generate hash signature and nonce and store into the same form table
            String amount = formRow.getProperty("AMOUNT");
            String currency = formRow.getProperty("CURRENCY");
            String order = formRow.getProperty("ORDER");
            String description = formRow.getProperty("DESC");
            String email = formRow.getProperty("EMAIL");
            String merchantName = formRow.getProperty("MERCH_NAME");
            String merchantUrl = formRow.getProperty("MERCH_URL");
            String merchant = formRow.getProperty("MERCHANT");
            String terminal = formRow.getProperty("TERMINAL");
            String trType = formRow.getProperty("TRTYPE");
            String country = formRow.getProperty("COUNTRY");
            String merchantGmt = formRow.getProperty("MERCH_GMT");
            String timeStamp = formRow.getProperty("TIMESTAMP");
            String backRef = formRow.getProperty("BACKREF");

            // generate nonce
            String nonce = generateNonce(30);

            // generate the signature
            StringBuilder preparedString = new StringBuilder();

            // format the amount
            String formattedAmount = amount;
            try {
                double amountDouble = Double.parseDouble(amount);
                DecimalFormat decimalFormat = new DecimalFormat("#.00");
                formattedAmount = decimalFormat.format(amountDouble);
            } catch (NumberFormatException ex) {
                LogUtil.error(getClassName(), ex, ex.getMessage());
            }

            appendLengthPrefixed(preparedString, terminal);
            appendLengthPrefixed(preparedString, trType);
            appendLengthPrefixed(preparedString, formattedAmount);
            appendLengthPrefixed(preparedString, currency);
            appendLengthPrefixed(preparedString, order);
            appendLengthPrefixed(preparedString, merchant);
            appendLengthPrefixed(preparedString, email);
            appendLengthPrefixed(preparedString, backRef);
            appendLengthPrefixed(preparedString, timeStamp);
            appendLengthPrefixed(preparedString, merchantName);
            appendLengthPrefixed(preparedString, country);
            appendLengthPrefixed(preparedString, merchantUrl);
            appendLengthPrefixed(preparedString, merchantGmt);
            appendLengthPrefixed(preparedString, description);
            appendLengthPrefixed(preparedString, nonce);

            String macSourceString = preparedString.toString();

            byte[] keyBytes = hexStringToByteArray(secretKey);
            SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "HmacSHA256");

            String encryptedMac = "";
            try {
                Mac mac = Mac.getInstance("HmacSHA256");
                mac.init(secretKeySpec);
                byte[] hmacSha256 = mac.doFinal(macSourceString.getBytes(StandardCharsets.UTF_8));
                encryptedMac = bytesToHex(hmacSha256);
            } catch (NoSuchAlgorithmException | InvalidKeyException ex) {
                LogUtil.error(getClassName(), ex, ex.getMessage());
            }

            PluginProperties pluginProperties = new PluginProperties();
            pluginProperties.setPaymentFormId(paymentFormId);
            pluginProperties.setResponseFormId(responseFormId);
            pluginProperties.setSecretKey(secretKey);
            pluginProperties.setRedirectUserviewMenu(redirectUserviewMenu);
            pluginProperties.setRedirectUserviewMenuFormID(redirectUserviewMenuFormID);

            String pp = generatePluginProperties(pluginProperties);

            // now update the record
            FormRowSet rows = new FormRowSet();
            FormRow row = new FormRow();
            row.setId(recordId);
            row.put("NONCE", nonce);
            row.put("P_SIGN", encryptedMac.toUpperCase());
            row.put("PLUGIN_PP", pp);
            row.put("REQ_MAC_SRC", macSourceString);
            row.put("id", recordId);
            //PLUGIN_PP
            rows.add(row);

            String tableName = appService.getFormTableName(appDef, paymentFormId);
            appService.storeFormData(paymentFormId, tableName, rows, recordId);
        }

        return null;
    }

    @Override
    public void webService(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        if ("POST".equalsIgnoreCase(request.getMethod())) {

            AppService appService = (AppService) FormUtil.getApplicationContext().getBean("appService");
            FormDataDao formDataDao = (FormDataDao) AppUtil.getApplicationContext().getBean("formDataDao");
            String paymentStatus = "SUCCESSFUL";

            String merchant = AppUtil.processHashVariable("#appVariable." + MERCHANT + "#", null, null, null);
            String terminal = AppUtil.processHashVariable("#appVariable." + TERMINAL + "#", null, null, null);

            Enumeration<String> parameterNames = request.getParameterNames();
            Map<String, String> formData = new HashMap<>();
            
            // Iterate over the parameter names and append each parameter and its value to the response content
            while (parameterNames.hasMoreElements()) {
                String paramName = parameterNames.nextElement();
                String paramValue = request.getParameter(paramName);
                formData.put(paramName, paramValue);
                LogUtil.info(getClassName(), paramName + ":" + paramValue);
            }

            if (!formData.isEmpty()) {
                String action = formData.get("ACTION");
                String rc = formData.get("RC");
                String approval = formData.get("APPROVAL");
                String currency = formData.get("CURRENCY");
                String amountStr = formData.get("AMOUNT");
                String trType = formData.get("TRTYPE");
                String order = formData.get("ORDER");
                String rrn = formData.get("RRN");
                String timeStamp = formData.get("TIMESTAMP");
                String intRef = formData.get("INT_REF");
                String nonce = formData.get("NONCE");
                String responseSignature = formData.get("P_SIGN");

                String formattedAmount = amountStr;
                try {
                    double amount = Double.parseDouble(amountStr);
                    DecimalFormat decimalFormat = new DecimalFormat("#.00");
                    formattedAmount = decimalFormat.format(amount);
                } catch (NumberFormatException e) {

                }

                StringBuilder preparedString = new StringBuilder();

                appendLengthPrefixed(preparedString, action);
                appendLengthPrefixed(preparedString, rc);
                appendLengthPrefixed(preparedString, approval);
                appendLengthPrefixed(preparedString, currency);
                appendLengthPrefixed(preparedString, formattedAmount);
                appendLengthPrefixed(preparedString, terminal);
                appendLengthPrefixed(preparedString, trType);
                appendLengthPrefixed(preparedString, order);
                appendLengthPrefixed(preparedString, rrn);
                appendLengthPrefixed(preparedString, merchant);
                appendLengthPrefixed(preparedString, timeStamp);
                appendLengthPrefixed(preparedString, intRef);
                appendLengthPrefixed(preparedString, nonce);

                String macSourceString = preparedString.toString();
                String secretKey = AppUtil.processHashVariable("#appVariable." + SECRET + "#", null, null, null);

                byte[] keyBytes = hexStringToByteArray(secretKey);

                SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "HmacSHA256");

                Mac mac;
                String encryptedMac = "";
                try {
                    mac = Mac.getInstance("HmacSHA256");
                    mac.init(secretKeySpec);
                    byte[] hmacSha256 = mac.doFinal(macSourceString.getBytes(StandardCharsets.UTF_8));
                    encryptedMac = bytesToHex(hmacSha256);
                } catch (NoSuchAlgorithmException | InvalidKeyException ex) {
                    LogUtil.error(getClassName(), ex, ex.getMessage());
                }

                encryptedMac = encryptedMac.toUpperCase();
                responseSignature = responseSignature.toUpperCase();
                if (!responseSignature.equals(encryptedMac)) {
                    paymentStatus = "FAILED";
                }

                String paymentFormId = AppUtil.processHashVariable("#appVariable." + FORM_ID + "#", null, null, null);
                AppDefinition appDef = AppUtil.getCurrentAppDefinition();
                String appId = appDef.getAppId();
                String tableName = appService.getFormTableName(appDef, paymentFormId);
                FormRowSet srows = formDataDao.find(paymentFormId, tableName, "where e.customProperties.ORDER = ?", new String[]{order}, null, true, 0, 1);
                if (srows != null && !srows.isEmpty()) {
                    String recordId = srows.get(0).getId();

                    FormRowSet rows = new FormRowSet();
                    FormRow row = new FormRow();
                    row.setId(recordId);
                    row.put("ACTION", action);
                    row.put("RC", rc);
                    row.put("APPROVAL", approval);
                    row.put("RRN", rrn);
                    row.put("INT_REF", intRef);
                    row.put("RES_TIMESTAMP", timeStamp);
                    row.put("RES_NONCE", nonce);
                    row.put("RES_P_SIGN", responseSignature);
                    row.put("RES_SIGN", encryptedMac.toUpperCase());
                    row.put("P_STATUS", paymentStatus);
                    row.put("RES_MAC_SRC", macSourceString);
                    row.put("id", recordId);
                    //PLUGIN_PP
                    rows.add(row);

                    appService.storeFormData(paymentFormId, tableName, rows, recordId);

                    // perfom redirect
                    String redirectUserviewMenu = AppUtil.processHashVariable("#appVariable." + USERVIEW_ID + "#", null, null, null);
                    String redirectUserviewMenuFormID = AppUtil.processHashVariable("#appVariable." + USERVIEW_MENU_ID + "#", null, null, null);
                    String baseUrl = AppUtil.processHashVariable("#request.baseURL#", null, null, null) + "/web/userview/";
                    baseUrl += appId + "/" + redirectUserviewMenu + "/_/" + redirectUserviewMenuFormID + "?id=" + recordId;
                    response.sendRedirect(baseUrl);
                }
            }
        }

    }

    private String generatePluginProperties(PluginProperties pluginProperties) {
        Gson gson = new Gson();
        String jsonString = gson.toJson(pluginProperties);
        return jsonString;
    }

    public static String generateNonce(int length) {
        if (length < 1 || length > 32) {
            throw new IllegalArgumentException("Length must be between 1 and 32");
        }

        StringBuilder nonce = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            int index = RANDOM.nextInt(CHARACTERS.length());
            nonce.append(CHARACTERS.charAt(index));
        }

        return nonce.toString();
    }

    private void appendLengthPrefixed(StringBuilder sb, String value) {
        if (value == null || value.isEmpty()) {
            sb.append("-"); // Append '-' if the value is missing
        } else {
            sb.append(value.length()).append(value);
        }
    }

    private static byte[] hexStringToByteArray(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    // Helper function to convert a byte array to a hexadecimal string
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    @Override
    public String getName() {
        return "Kina Bank Payment Tool";
    }

    @Override
    public String getVersion() {
        return "8.0.0";
    }

    @Override
    public String getDescription() {
        return "Kina Bank Payment Tool";
    }

    @Override
    public String getLabel() {
        return "Kina Bank Payment Tool";
    }

    @Override
    public String getClassName() {
        return this.getClass().getName();
    }

    @Override
    public String getPropertyOptions() {
        return "";
    }

}
