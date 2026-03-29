package com.repoguard.service;

import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
public class CacheService {

    private final Map<String, String> cache = new HashMap<>();

    public boolean contains(String key) {
        return cache.containsKey(key);
    }

    public String get(String key) {
        return cache.get(key);
    }

    public void put(String key, String value) {
        cache.put(key, value);
    }
}
