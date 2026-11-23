# 중앙 서버 이미지. 부하 측정에서 CPU · 메모리를 운영 인스턴스와 같게 묶으려고 만들었다
# (compose.yaml 의 server 서비스 — t3.micro = 2 vCPU · 1 GiB).
#
# 항아리는 호스트에서 먼저 만든다 — 이미지 안에서 Gradle 을 돌리면 JDK 25 툴체인과
# 의존성을 매번 다시 받는다:
#
#   cd server && ./gradlew bootJar
#   docker compose -f compose.yaml --profile t3micro up -d --build
#
# 항아리가 없으면 아래 COPY 가 실패한다 — 조용히 옛 이미지를 쓰지 않는다.
FROM eclipse-temurin:25-jre

WORKDIR /app
# -plain.jar 은 제외한다 (의존성이 안 들어 있다).
COPY build/libs/warrant-server-*-SNAPSHOT.jar /app/warrant-server.jar

# 메모리가 1 GiB 뿐이라 JVM 에 전부 주면 컨테이너가 OOM 으로 죽는다.
# gRPC(Netty)는 힙 밖 직접 버퍼를 쓰므로 그것까지 묶어야 한다 —
# 기본값은 최대 힙과 같아서, 묶지 않으면 힙 + 직접 버퍼가 한도를 넘는다.
ENV JAVA_TOOL_OPTIONS="-XX:MaxRAMPercentage=60 -XX:MaxDirectMemorySize=128m -XX:+ExitOnOutOfMemoryError"

EXPOSE 8080 9090
ENTRYPOINT ["java", "-jar", "/app/warrant-server.jar"]
