package com.santander.app.service.utils;

import com.santander.app.config.Constants;
import java.util.Arrays;
import java.util.List;
import org.apache.commons.lang3.StringUtils;

public class PasswordUtils {

    private static final List<String> PATTERNS = Arrays.asList(".*[A-Z]+.*", ".*[a-z]+.*", ".*\\d+.*", ".*[^A-Za-z0-9]+.*");
    private static final long REQUIRED_PATTERNS = 4;
    private static final int LEVENSHTEIN_DISTANCE_REQUIRED = 4;

    public static boolean checkStrength(final String password) {
        return passwordStrength(password) >= REQUIRED_PATTERNS;
    }

    public static boolean isPasswordLengthInvalid(String password) {
        return (
            StringUtils.isEmpty(password) ||
            password.length() < Constants.PASSWORD_MIN_LENGTH ||
            password.length() > Constants.PASSWORD_MAX_LENGTH
        );
    }

    public static boolean isStringDistanceMetricValid(final String oldPassword, final String newPassword) {
        return getLevenshteinDistance(oldPassword, newPassword) >= LEVENSHTEIN_DISTANCE_REQUIRED;
    }

    private static long passwordStrength(final String password) {
        return PATTERNS.stream().filter(password::matches).count();
    }

    private static int getLevenshteinDistance(CharSequence s, CharSequence t) {
        if (s != null && t != null) {
            int n = s.length();
            int m = t.length();
            if (n == 0) {
                return m;
            } else if (m == 0) {
                return n;
            } else {
                if (n > m) {
                    CharSequence tmp = s;
                    s = t;
                    t = tmp;
                    n = m;
                    m = tmp.length();
                }

                int[] p = new int[n + 1];

                int i;
                for (i = 0; i <= n; p[i] = i++) {}

                for (int j = 1; j <= m; ++j) {
                    int upper_left = p[0];
                    char t_j = t.charAt(j - 1);
                    p[0] = j;

                    for (i = 1; i <= n; ++i) {
                        int upper = p[i];
                        int cost = s.charAt(i - 1) == t_j ? 0 : 1;
                        p[i] = Math.min(Math.min(p[i - 1] + 1, p[i] + 1), upper_left + cost);
                        upper_left = upper;
                    }
                }

                return p[n];
            }
        } else {
            throw new IllegalArgumentException("Strings must not be null");
        }
    }
}
