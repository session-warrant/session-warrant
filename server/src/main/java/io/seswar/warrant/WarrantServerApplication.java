package io.seswar.warrant;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * 컨트롤 플레인. 이 프로세스가 죽어도 이미 발급된 영장의 집행은 노드에서 계속된다(§17) —
 * 여기에 가용성 장치를 덧붙여 fail-close 로 만들지 말 것.
 */
@SpringBootApplication
public class WarrantServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(WarrantServerApplication.class, args);
    }
}
