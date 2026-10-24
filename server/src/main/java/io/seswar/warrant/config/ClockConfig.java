package io.seswar.warrant.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;

/** 서버의 "지금". 테스트는 이 빈을 고정 시계로 바꿔 끼운다. */
@Configuration
public class ClockConfig {

    @Bean
    Clock clock() {
        return Clock.systemUTC();
    }
}
