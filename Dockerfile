FROM gradle:8.7-jdk21 AS build
WORKDIR /app

COPY . .

RUN --mount=type=secret,id=GPR_USER \
    --mount=type=secret,id=GPR_TOKEN \
    export GPR_USER=$(cat /run/secrets/GPR_USER) && \
    export GPR_TOKEN=$(cat /run/secrets/GPR_TOKEN) && \
    gradle bootJar --no-daemon

FROM eclipse-temurin:21-jre
WORKDIR /app
COPY --from=build /app/build/libs/*.jar app.jar
ENTRYPOINT ["java", "-jar", "app.jar"]