package com.anomaly.platform;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.util.TimeZone;

@SpringBootApplication
public class AnomalyPlatformApplication {

    public static void main(String[] args) {

        /*
         * All timestamps are stored and compared in UTC. The PostgreSQL JDBC
         * driver forwards the JVM's default zone to the server as the
         * connection TimeZone, and PostgreSQL rejects legacy aliases such
         * as "Asia/Calcutta" ("invalid value for parameter TimeZone"), so
         * on a machine with such a default the application could not start
         * unless -Duser.timezone=UTC was passed by hand (as the IDE run
         * configuration happens to do). Pinning it here makes
         * `java -jar` behave identically everywhere. Must run before any
         * Spring or JDBC class initialises.
         */
        TimeZone.setDefault(TimeZone.getTimeZone("UTC"));

        SpringApplication.run(AnomalyPlatformApplication.class, args);
    }
}
