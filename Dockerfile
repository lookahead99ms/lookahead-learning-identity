FROM eclipse-temurin:21-jdk-alpine@sha256:82801f9dcdcbad5a05082aba8c86d1da5b72ccb498e71318b1f91b5a477887b3 AS build
WORKDIR /workspace
ENV GRADLE_USER_HOME=/tmp/gradle-cache
COPY gradlew ./
COPY gradle/wrapper/ gradle/wrapper/
RUN ./gradlew --no-daemon --version
COPY build.gradle settings.gradle gradle.lockfile ./
COPY src/ src/
RUN ./gradlew --no-daemon clean test bootJar \
    && mkdir /workspace/health \
    && javac --release 21 -d /workspace/health src/main/java/com/lookahead/identity/health/ContainerHealthcheck.java

FROM eclipse-temurin:21-jre-alpine@sha256:ac05c3c42b7c2f1a52c9bd52f01041fa1958231b15ebeae7420429cbc5baf474 AS runtime
WORKDIR /opt/lookahead
RUN addgroup -g 10001 lookahead && adduser -D -H -u 10001 -G lookahead lookahead
COPY --from=build --chown=10001:10001 /workspace/build/libs/lookahead-identity.jar /opt/lookahead/app.jar
COPY --from=build --chown=10001:10001 /workspace/health /opt/lookahead/health
USER 10001:10001
ENV LOOKAHEAD_BIND_ADDRESS=0.0.0.0 PORT=8080
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=5s --start-period=40s --retries=6 CMD ["java", "-cp", "/opt/lookahead/health", "com.lookahead.identity.health.ContainerHealthcheck"]
ENTRYPOINT ["java", "-jar", "/opt/lookahead/app.jar"]
