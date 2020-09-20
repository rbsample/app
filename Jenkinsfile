pipeline {
  agent {
    node {
      label 'build'
    }

  }
  stages {
    stage('Build App') {
      agent {
        node {
          label 'build'
        }

      }
      steps {
        sh '''
# Stop any running test containers from failed stages
stale_containers=$(docker ps | grep -E "(_web_1|_db_1)" | awk '{ print $NF }')
for container in $stale_containers
do
  docker stop $container
done
# Build image
docker-compose build
docker build --no-cache -t app_web:latest .
'''
      }
    }
 
    stage('SAST') {
      parallel {
        stage('Static Vulnerability Scan') {
          agent {
            node {
              label 'build'
            }

          }
          steps {
            sh '''# Scan dependencies for vulnerabilities
docker-compose up -d
web_container=$(docker ps  | grep web_1 | awk \'{print $NF}\')
docker exec ${web_container} gem install bundle-audit # brakeman hakiri
docker exec ${web_container} bundle install
docker exec ${web_container} bundle-audit | tee output
docker-compose down
if grep "Vulnerabilities found!" output; then exit 1;fi '''
          }
        }

        stage('PII Scan') {
          agent {
            node {
              label 'build'
            }

          }
          steps {
            sh '''
temp_dir=$(mktemp -d)
wget https://github.com/ankane/pdscan/releases/download/v0.1.1/pdscan_0.1.1_Linux_x86_64.zip -P ${temp_dir}
unzip -p ${temp_dir}/pdscan_0.1.1_Linux_x86_64.zip pdscan > ${temp_dir}/pdscan
chmod +x ${temp_dir}/pdscan
# scan all files (doesn\'t work well recursively so we are doing it with find )
> output
find ./app -type f -exec ${temp_dir}/pdscan file://{} \\; | tee -a output
if grep ": found" output; then exit 1;fi '''
          }
        }

      }
    }
        stage('AV Scan') {
          agent {
            node {
              label 'build'
            }

          }
          steps {
            sh '''# Anti Malware Scan
# Install clamdscan
# Start ClamAV container & create network
# docker run -d -p 3310:3310 --name clamav openbridge/clamav 
# docker network create clamav
# docker network connect clamav clamav
# Start Container
docker-compose up -d
# Create DB
docker-compose run web rake db:create
# get web container name
web_container=$(docker ps  | grep web_1 | awk \'{print $NF}\')
# Connect to network if not already
docker network connect clamav ${web_container}
clam_ip=$(docker inspect -f "{{ .NetworkSettings.Networks.clamav.IPAddress }}" clamav)

# Create config file
cat << EOF > ./clamd.conf
LogSyslog yes
PidFile /var/run/clamd.pid
FixStaleSocket true
LocalSocketGroup clamav
LocalSocketMode 666
TemporaryDirectory /tmp
DatabaseDirectory /var/lib/clamav
TCPSocket 3310
TCPAddr ${clam_ip}
MaxConnectionQueueLength 200
MaxThreads 10
ReadTimeout 400
Foreground true
StreamMaxLength 100M
HeuristicScanPrecedence yes
StructuredDataDetection no
#StructuredSSNFormatNormal yes
ScanPE yes
ScanELF yes
ScanOLE2 yes
ScanPDF yes
ScanSWF yes
ScanMail yes
PhishingSignatures yes
PhishingScanURLs yes
ScanArchive yes
ArchiveBlockEncrypted no
MaxScanSize 1000M
MaxFileSize 1000M
Bytecode yes
BytecodeSecurity TrustSigned
BytecodeTimeout 240000
EOF

# Scan inside the container
docker exec ${web_container} apt-get install -y clamdscan
docker cp ./clamd.conf ${web_container}:/etc/clamav/clamd.conf
docker exec ${web_container} clamdscan --version
# Create eicar file
# echo \'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*\' > eicar
# gem install EICAR
# Scan current application folder
cat << EOF > ./scan.sh
clamdscan --stream /myapp
# Scan gem installed paths
gem_paths=\\$(gem environment | sed -n \'/GEM PATHS/,/GEM/p\' | grep -v GEM | awk \'{ print \\$NF }\')
for gem_path in \\${gem_paths}
do
  echo "Scanning \\${gem_path}/gems/"
  clamdscan --stream \\${gem_path}/gems/
done 
EOF
docker cp ./scan.sh ${web_container}:/scan.sh
> output
docker exec ${web_container} bash /scan.sh | tee output
# Disconnect 
docker network disconnect clamav ${web_container}
# Shut down
docker-compose down
# Send signal
if grep "FOUND" output; then exit 1;fi '''
          }
        }

        stage('XSS Scan') {
          agent {
            node {
              label 'build'
            }

          }
          steps {
            sh '''# Xss Scan
# Start Container
docker-compose up -d
# Create DB
docker-compose run web rake db:create
# install preerquisites
temp_dir=$(mktemp -d)
git clone https://github.com/pwn0sec/PwnXSS ${temp_dir}
# Scan
> output
python3 ${temp_dir}/pwnxss.py -u http://localhost:3000/ | tee output
docker-compose down
# Send signal
if grep "CRITICAL" output; then exit 1;fi  '''
          }
        }

    stage('Stop & Cleanup') {
      agent {
        node {
          label 'build'
        }

      }
      steps {
        sh '''docker-compose down
# Cleanup stale containers
docker container prune --force
docker image prune --force
# Cleanup temporary files
rm -rf /tmp/tmp.*
'''
      }
    }
    stage('Publish Image') {
      agent {
        node {
          label 'build'
        }

      }
      steps {
        sh '''aws_account_id=$(curl -s http://169.254.169.254/latest/dynamic/instance-identity/document|grep accountId| awk \'{print $3}\'|sed  \'s/"//g\'|sed \'s/,//g\')
repo_name="rbsample"
region="eu-west-1"
# authenticate ECR
aws ecr get-login-password --region eu-west-1 | docker login --username AWS --password-stdin ${aws_account_id}.dkr.ecr.${region}.amazonaws.com
# tag app
docker tag app_web:latest ${aws_account_id}.dkr.ecr.${region}.amazonaws.com/${repo_name}:latest
# push app
docker push ${aws_account_id}.dkr.ecr.${region}.amazonaws.com/${repo_name}:latest'''
      }
    }

    stage('Host Scan') {
      parallel {
        stage('CIS') {
          agent {
            node {
              label 'build'
            }

          }
          steps {
            sh '''# Run CIS Check for the Ubuntu host
temp_dir=$(mktemp -d)
git clone https://github.com/bats-core/bats-core.git ${temp_dir}
${temp_dir}/install.sh /usr/local
git clone https://github.com/cloudogu/CIS-Ubuntu-18.04.git ${temp_dir}/CIS-Ubuntu-18.04
# For the moment we don't want the build to fail, so trapping the exit
> output
bats ${temp_dir}//CIS-Ubuntu-18.04/*/ | grep "not ok" | tee output
'''
          }
        }

        stage('Docker-Bench') {
          agent {
            node {
              label 'build'
            }

          }
          steps {
            sh '''# Run docker-bench-security for security assesment
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sh docker-bench-security.sh
# Cleanup
cd ../
rm -rf ./docker-bench-security'''
          }
        }

      }
    }

    stage('Deploy Image') {
      agent {
        node {
          label 'build'
        }

      }
      steps {
        sh '# Intentionally left blank'
      }
    }

  }
}
