package com.dast.vulnapp.controller;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Java 8 compatibility shim. Spring Boot 2.7 targets Java 8, which lacks the
 * Java 9 collection factory methods (Map.of / List.of / Set.of) used by the
 * shared controller sources. These helpers provide equivalent behaviour so the
 * exact same vulnerable controllers compile under Java 8.
 */
public final class Compat {

    private Compat() {
    }

    /** Replacement for the Java 9 Map.of(k1, v1, k2, v2, ...). Keys are stringified. */
    public static Map<String, Object> map(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i + 1 < kv.length; i += 2) {
            m.put(String.valueOf(kv[i]), kv[i + 1]);
        }
        return m;
    }

    /** Replacement for the Java 9 List.of(...). */
    @SafeVarargs
    public static <T> List<T> list(T... items) {
        return new ArrayList<>(Arrays.asList(items));
    }

    /** Replacement for the Java 9 Set.of(...). */
    @SafeVarargs
    public static <T> Set<T> set(T... items) {
        return new LinkedHashSet<>(Arrays.asList(items));
    }
}
