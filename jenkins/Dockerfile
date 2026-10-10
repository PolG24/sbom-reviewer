FROM jenkins/jenkins:2.568.3-jdk21

USER root
RUN apt-get update \
    && apt-get install --yes --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*
USER jenkins
