# RTE-430 elasticsearch and python-salm-fs disabled due to DSM connection failures
# RTE-534 Disable until the test is made more stable - tools/app-test-infra/apps/mariadb
SUBDIRS = \
	tools/app-test-infra/apps/bash \
	tools/app-test-infra/apps/invalid-auth-config \
	tools/app-test-infra/apps/nginx/self-proxy \
	tools/app-test-infra/apps/python-default-appcert \
	tools/app-test-infra/apps/python-minver \
	tools/app-test-infra/apps/python-web-server \
	tools/app-test-infra/apps/java/websphere \
	tools/app-test-infra/apps/hostname \
	tools/app-test-infra/apps/salmiac/python-web-server-localhost \
	tools/app-test-infra/apps/salmiac/bitnami-postgresql \
