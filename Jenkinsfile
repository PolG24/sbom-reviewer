pipeline {
    agent { label 'python312' }

    stages {
        stage('Install') {
            steps {
                sh 'uv sync --locked'
            }
        }

        stage('Tests') {
            steps {
                catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                    sh '''
                        set +e
                        uv run --locked pytest > test-output.txt 2>&1
                        status=$?
                        printf '%s\n' "$status" > test-status.txt
                        cat test-output.txt
                        exit "$status"
                    '''
                }
            }
        }

        stage('Dependency audit') {
            steps {
                catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                    sh '''
                        set +e
                        sh scripts/audit-dependencies.sh > audit-output.txt 2>&1
                        status=$?
                        printf '%s\n' "$status" > audit-status.txt
                        cat audit-output.txt
                        exit "$status"
                    '''
                }
            }
        }

        stage('Report results') {
            steps {
                script {
                    def testStatus = fileExists('test-status.txt')
                        ? readFile('test-status.txt').trim()
                        : 'not run'
                    def auditStatus = fileExists('audit-status.txt')
                        ? readFile('audit-status.txt').trim()
                        : 'not run'

                    if (testStatus != '0' || auditStatus != '0') {
                        error("Tests exited ${testStatus}; dependency audit exited ${auditStatus}")
                    }
                }
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: '*-output.txt,*-status.txt', allowEmptyArchive: true
        }
    }
}
