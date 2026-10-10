FROM python:3.12-slim-trixie

COPY --from=ghcr.io/astral-sh/uv:0.9.18 /uv /uvx /usr/local/bin/

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates curl git openjdk-21-jre-headless \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 1000 jenkins \
    && useradd --uid 1000 --gid jenkins --create-home --shell /bin/sh jenkins \
    && mkdir -p /home/jenkins/agent \
    && chown -R jenkins:jenkins /home/jenkins

COPY jenkins/agent/entrypoint.sh /usr/local/bin/jenkins-agent
RUN chmod +x /usr/local/bin/jenkins-agent

USER jenkins
WORKDIR /home/jenkins/agent
ENTRYPOINT ["jenkins-agent"]
