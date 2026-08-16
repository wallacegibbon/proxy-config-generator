##  Usage: Copy this file to shell init (like ~/.zshrc, ~/.bashrc) or source this file.
proxyon() {
	export all_proxy=socks5://127.0.0.1:7890
	export http_proxy=http://127.0.0.1:7890
	export https_proxy=http://127.0.0.1:7890
	export no_proxy="localhost,127.0.0.0/8,::1,192.168.0.0/16,172.16.0.0/12,10.0.0.0/8"
	export ALL_PROXY=socks5://127.0.0.1:7890
	export HTTP_PROXY=http://127.0.0.1:7890
	export HTTPS_PROXY=http://127.0.0.1:7890
	export NO_PROXY="localhost,127.0.0.0/8,::1,192.168.0.0/16,172.16.0.0/12,10.0.0.0/8"
	printf "\033[32m[√] Proxy env set up!\033[0m\n"
}

proxyoff() {
	unset all_proxy
	unset http_proxy
	unset https_proxy
	unset no_proxy
	unset ALL_PROXY
	unset HTTP_PROXY
	unset HTTPS_PROXY
	unset NO_PROXY
	printf "\033[31m[√] Proxy env cleaned up.\033[0m\n"
}
