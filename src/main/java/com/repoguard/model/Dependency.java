package com.repoguard.model;

public class Dependency {

    private String artifactId;
    private String version;

    public Dependency(String artifactId, String version) {
        this.artifactId = artifactId;
        this.version = version;
    }

    public String getArtifactId() {
        return artifactId;
    }

    public String getVersion() {
        return version;
    }
}
