FROM debian:bookworm-slim

RUN apt-get update \
	&& DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
		fcgiwrap \
		git \
		nginx-light \
	&& rm -rf /var/lib/apt/lists/*

RUN git config --global init.defaultBranch main
RUN mkdir -p /var/lib/git /run/fcgiwrap

COPY --chmod=755 <<'EOF' /entrypoint.sh
#!/usr/bin/env bash
set -euo pipefail

: "${USERNAME:?set USERNAME for HTTP basic auth}"
: "${BCRYPT_PASSWORD:?set BCRYPT_PASSWORD containing a bcrypt hash}"
: "${REPO_NAME:?set REPO_NAME for the bare repository (without .git)}"

htpasswd_file=/etc/nginx/conf.d/htpasswd

echo "${USERNAME}:${BCRYPT_PASSWORD}" > "${htpasswd_file}"
chown www-data:www-data "${htpasswd_file}"
chmod 640 "${htpasswd_file}"

repo_path="/var/lib/git/${REPO_NAME}.git"
if [ ! -d "${repo_path}" ]; then
	git init --bare "${repo_path}"
	chown -R www-data:www-data "${repo_path}"
fi

cat > /etc/nginx/nginx.conf <<'NGINXMAIN'
user www-data;
worker_processes auto;
pid /run/nginx.pid;

events {
	worker_connections 1024;
}

http {
	include /etc/nginx/mime.types;
	default_type application/octet-stream;

	log_format main '$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"';
	access_log /dev/stdout main;
	error_log /dev/stderr warn;

	sendfile on;
	keepalive_timeout 65;

	# Basic rate limiting to slow repeated auth attempts per client IP.
	limit_req_zone $binary_remote_addr zone=auth_limit:10m rate=5r/m;

	include /etc/nginx/sites-enabled/*;
}
NGINXMAIN

cat > /etc/nginx/sites-available/default <<'NGINXCONF'
server {
	listen 8080 default_server;
	listen [::]:8080 default_server;
	server_name _;

	location / {
		auth_basic "qault git server";
		auth_basic_user_file /etc/nginx/conf.d/htpasswd;

		include fastcgi_params;
		fastcgi_param GIT_HTTP_EXPORT_ALL "";
		fastcgi_param GIT_PROJECT_ROOT /var/lib/git;
		fastcgi_param PATH_INFO $uri;
		fastcgi_param SCRIPT_FILENAME /usr/lib/git-core/git-http-backend;
		fastcgi_param REMOTE_USER $remote_user;
		fastcgi_pass unix:{{SOCKET_PATH}};
		limit_req zone=auth_limit burst=10 nodelay;
	}
}
NGINXCONF

mkdir -p /etc/nginx/sites-enabled
ln -sf /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default

mkdir -p /run/fcgiwrap
chown www-data:www-data /run/fcgiwrap

socket_path="/run/fcgiwrap/fcgiwrap.sock"
sed -i "s|{{SOCKET_PATH}}|${socket_path}|g" /etc/nginx/sites-available/default

su -s /bin/sh -c "fcgiwrap -s unix:${socket_path}" www-data &

trap "kill 0" EXIT

exec nginx -g 'daemon off;'
EOF

EXPOSE 8080

ENTRYPOINT ["/entrypoint.sh"]
