FROM adoptopenjdk/openjdk11:jre-11.0.6_10-alpine

RUN adduser -D -s /bin/sh foundation

WORKDIR /home/foundation/

COPY target/*.jar /home/foundation/app.jar 
ADD entrypoint.sh entrypoint.sh

ENTRYPOINT ["./entrypoint.sh"]

EXPOSE 8443