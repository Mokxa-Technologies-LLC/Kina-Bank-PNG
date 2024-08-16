package org.joget.marketplace.model;

public class PluginProperties {

    private String secretKey;
    private String paymentFormId;
    private String responseFormId;
    private String redirectUserviewMenu;
    private String redirectUserviewMenuFormID;

    public String getSecretKey() {
        return secretKey;
    }

    public void setSecretKey(String secretKey) {
        this.secretKey = secretKey;
    }

    public String getPaymentFormId() {
        return paymentFormId;
    }

    public void setPaymentFormId(String paymentFormId) {
        this.paymentFormId = paymentFormId;
    }

    public String getResponseFormId() {
        return responseFormId;
    }

    public void setResponseFormId(String responseFormId) {
        this.responseFormId = responseFormId;
    }

    public String getRedirectUserviewMenu() {
        return redirectUserviewMenu;
    }

    public void setRedirectUserviewMenu(String redirectUserviewMenu) {
        this.redirectUserviewMenu = redirectUserviewMenu;
    }

    public String getRedirectUserviewMenuFormID() {
        return redirectUserviewMenuFormID;
    }

    public void setRedirectUserviewMenuFormID(String redirectUserviewMenuFormID) {
        this.redirectUserviewMenuFormID = redirectUserviewMenuFormID;
    }

    

}
