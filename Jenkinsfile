pipeline {
    agent any

    options {
        timestamps()
        disableConcurrentBuilds()
    }

    environment {
        IMAGE_NAME = 'api-gateway'
        AWS_REGION = 'ap-northeast-2'
        ECR_REPOSITORY = 'erumpay/api-gateway'
        AWS_CREDENTIALS_ID = 'aws-erumpay-ecr'
        INFRA_REPOSITORY_URL = 'https://github.com/ErumPay/erumpay-infra.git'
        INFRA_BRANCH = 'develop'
        INFRA_CREDENTIALS_ID = 'github-erumpay-infra-write'
        INFRA_HELM_VALUES_PATH = 'helm/values/dev/api-gateway.yaml'
        GIT_COMMITTER_NAME = 'erumpay-jenkins'
        GIT_COMMITTER_EMAIL = 'jenkins@erumpay.local'
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Prepare Image Metadata') {
            steps {
                script {
                    env.IMAGE_TAG = env.GIT_COMMIT?.take(7)
                    if (!env.IMAGE_TAG) {
                        env.IMAGE_TAG = sh(script: 'git rev-parse --short HEAD', returnStdout: true).trim()
                    }
                    echo "Image tag: ${env.IMAGE_TAG}"
                }
            }
        }

        stage('Gradle Build') {
            steps {
                sh 'chmod +x ./gradlew'
                sh './gradlew test bootJar --no-daemon --max-workers=1 --build-cache'
            }
        }

        stage('Archive Artifact') {
            steps {
                archiveArtifacts artifacts: 'build/libs/*.jar', fingerprint: true, onlyIfSuccessful: true
            }
        }

        stage('Docker Build') {
            steps {
                sh "docker build -f Dockerfile.ci -t ${IMAGE_NAME}:${IMAGE_TAG} ."
            }
        }

        stage('ECR Push') {
            steps {
                withCredentials([[$class: 'AmazonWebServicesCredentialsBinding', credentialsId: "${AWS_CREDENTIALS_ID}"]]) {
                    script {
                        def accountId = sh(script: 'aws sts get-caller-identity --query Account --output text', returnStdout: true).trim()
                        def ecrRegistry = "${accountId}.dkr.ecr.${env.AWS_REGION}.amazonaws.com"
                        env.ECR_IMAGE_REPOSITORY = "${ecrRegistry}/${env.ECR_REPOSITORY}"
                        env.ECR_IMAGE = "${env.ECR_IMAGE_REPOSITORY}:${env.IMAGE_TAG}"
                        sh "aws ecr get-login-password --region ${AWS_REGION} | docker login --username AWS --password-stdin ${ecrRegistry}"
                        sh "docker tag ${IMAGE_NAME}:${IMAGE_TAG} ${ECR_IMAGE}"
                        sh "docker push ${ECR_IMAGE}"
                    }
                }
            }
        }

        stage('Update Infra Image Tag') {
            when {
                branch 'main'
            }
            steps {
                withCredentials([usernamePassword(
                    credentialsId: "${INFRA_CREDENTIALS_ID}",
                    usernameVariable: 'GIT_USERNAME',
                    passwordVariable: 'GIT_PASSWORD'
                )]) {
                    dir('erumpay-infra') {
                        checkout([
                            $class: 'GitSCM',
                            branches: [[name: "*/${INFRA_BRANCH}"]],
                            userRemoteConfigs: [[url: "${INFRA_REPOSITORY_URL}", credentialsId: "${INFRA_CREDENTIALS_ID}"]]
                        ])

                        script {
                            if (!fileExists(env.INFRA_HELM_VALUES_PATH)) {
                                error "Infra Helm values file not found: ${env.INFRA_HELM_VALUES_PATH}"
                            }
                            def values = readFile(env.INFRA_HELM_VALUES_PATH)
                            values = values.replaceFirst('(?m)^\\s*repository:\\s*.+$', "  repository: \"${env.ECR_IMAGE_REPOSITORY}\"")
                            values = values.replaceFirst('(?m)^\\s*tag:\\s*.+$', "  tag: \"${env.IMAGE_TAG}\"")
                            writeFile file: env.INFRA_HELM_VALUES_PATH, text: values
                        }

                        sh '''
                            git config user.name "$GIT_COMMITTER_NAME"
                            git config user.email "$GIT_COMMITTER_EMAIL"

                            if git diff --quiet -- "$INFRA_HELM_VALUES_PATH"; then
                              echo "No infra image tag changes to commit."
                            else
                              git add "$INFRA_HELM_VALUES_PATH"
                              git commit -m "chore: update $IMAGE_NAME image tag to $IMAGE_TAG"
                              git remote set-url origin "https://${GIT_USERNAME}:${GIT_PASSWORD}@github.com/ErumPay/erumpay-infra.git"
                              git push origin "HEAD:${INFRA_BRANCH}"
                            fi
                        '''
                    }
                }
            }
        }
    }

    post {
        always {
            junit testResults: 'build/test-results/test/*.xml', allowEmptyResults: true
            sh 'docker image prune -f --filter "until=24h" || true'
            sh 'docker builder prune -f --filter "until=24h" || true'
        }
    }
}
