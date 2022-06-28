package com.santander.app.domain.azure.b2c;

import java.util.ArrayList;
import java.util.List;

public class AuthorizeResponse {

    private List<Key> keys = new ArrayList<>();

    public List<Key> getKeys() {
        return keys;
    }

    public void setKeys(List<Key> keys) {
        this.keys = keys;
    }
}
