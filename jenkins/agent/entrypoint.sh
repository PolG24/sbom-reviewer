#!/bin/sh
set -eu

while [ -z "${JENKINS_AGENT_SECRET:-}" ]; do
    echo "Set JENKINS_AGENT_SECRET in .env after creating the python312 node in Jenkins."
    sleep 30
done

curl --fail --silent --show-error \
    --retry 20 --retry-delay 3 --retry-connrefused \
    "${JENKINS_URL}/jnlpJars/agent.jar" \
    --output /home/jenkins/agent/agent.jar

exec java -jar /home/jenkins/agent/agent.jar \
    -url "${JENKINS_URL}/" \
    -secret "${JENKINS_AGENT_SECRET}" \
    -name "${JENKINS_AGENT_NAME}" \
    -webSocket \
    -workDir /home/jenkins/agent
