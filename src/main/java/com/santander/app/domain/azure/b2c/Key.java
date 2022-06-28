package com.santander.app.domain.azure.b2c;

public class Key {


    private String kid;
    private long nbf;
    private String use;
    private String kty;
    private String e;
    private String n;

    public String getKid() {
        return kid;
    }

    public void setKid(String kid) {
        this.kid = kid;
    }

    public long getNbf() {
        return nbf;
    }

    public void setNbf(long nbf) {
        this.nbf = nbf;
    }

    public String getUse() {
        return use;
    }

    public void setUse(String use) {
        this.use = use;
    }

    public String getKty() {
        return kty;
    }

    public void setKty(String kty) {
        this.kty = kty;
    }

    public String getE() {
        return e;
    }

    public void setE(String e) {
        this.e = e;
    }

    public String getN() {
        return n;
    }

    public void setN(String n) {
        this.n = n;
    }
}
