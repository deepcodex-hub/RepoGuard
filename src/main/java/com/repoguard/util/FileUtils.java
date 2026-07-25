package com.repoguard.util;

import java.io.File;

public class FileUtils {

    /**
     * Recursively deletes a directory and all its contents.
     * Returns true if deletion was fully successful, false otherwise.
     */
    public static boolean deleteDirectory(File directory) {
        if (directory == null || !directory.exists()) return true;

        if (directory.isDirectory()) {
            File[] files = directory.listFiles();
            if (files != null) {
                for (File file : files) {
                    if (!deleteDirectory(file)) return false;
                }
            }
        }
        return directory.delete();
    }
}
