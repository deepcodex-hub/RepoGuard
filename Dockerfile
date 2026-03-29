# Use Java 17
FROM openjdk:17-jdk-slim

# Copy jar file
COPY target/repoguard-0.0.1-SNAPSHOT.jar app.jar

# Run the app
ENTRYPOINT ["java","-jar","/app.jar"]