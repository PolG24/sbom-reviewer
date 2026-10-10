# Local Jenkins

This project includes a Jenkins controller and Python 3.12 agent for local CI.
Docker Engine and the Compose plugin are required.

Start Jenkins from the repository root:

```bash
docker compose up -d --build
```

Open `http://localhost:8080`. To unlock Jenkins, print its initial password:

```bash
docker compose exec jenkins cat /var/jenkins_home/secrets/initialAdminPassword
```

After unlocking, skip suggested plugins. Install **Pipeline** (`workflow-aggregator`)
and **Git** from **Manage Jenkins → Plugins → Available plugins**. Restart Jenkins
if prompted.

Create the inbound build agent from **Manage Jenkins → Nodes → New Node**:

- Name: `python312`; choose **Permanent Agent**.
- Executors: `1`.
- Remote root: `/home/jenkins/agent`.
- Labels: `python312`.
- Launch method: **Launch agent by connecting it to the controller**; enable
  WebSocket if offered.

Copy that node's secret into the ignored `.env` file:

```dotenv
JENKINS_AGENT_SECRET=copy-the-node-secret-here
```

Recreate the agent to load the secret, if needed:

```bash
docker compose up -d --force-recreate jenkins-agent
```

Confirm that `python312` is online on the Nodes page. The agent image provides
Python 3.12 and uv 0.9.18.

Create a **Pipeline** job. Under **Pipeline**, choose **Pipeline script from
SCM**, select **Git**, and use:

- Repository URL: `file:///opt/sbom-reviewer.git`
- Branch specifier: `*/main`
- Script path: `Jenkinsfile`

Save the job and select **Build Now**. The read-only Git mount makes local
repository history available without mounting `.env` into the containers.

The test and audit stages save their output and status before reporting failures,
so both run even when one fails. Jenkins archives both outputs. The audit scans
locked runtime and development dependencies, excluding only the local editable
application package; it fails on known vulnerabilities, lookup errors, or
unsupported dependencies.

Jenkins is bound to localhost and should stay local. Its `jenkins_home` named
volume preserves job configuration across `docker compose down` and `up`; avoid
`docker compose down -v` if you want to keep that data.
