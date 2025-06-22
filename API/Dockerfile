# Build stage
FROM maven:3.9.9-ibm-semeru-21-noble AS build
COPY src /app/src
COPY pom.xml /app
RUN mvn -f /app/pom.xml clean test package

# Package stage
FROM openjdk:25-ea-21-slim-bullseye
COPY --from=build /app/target/*.jar app.jar
ENTRYPOINT ["java","-jar","/app.jar"]