# How test input files were generated

```
../build/h3-header-generator \
	-H 'accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9' \
	-H 'accept-encoding: gzip, deflate, br' \
	-H 'accept-language: en-US,en;q=0.9,ja;q=0.8,ja-JP;q=0.7' \
	-H 'cache-control: no-cache' \
	-H 'pragma: no-cache' \
	-H 'sec-ch-ua: " Not A;Brand";v="99", "Chromium";v="90", "Google Chrome";v="90"' \
	-H 'sec-ch-ua-mobile: ?0' \
	-H 'sec-fetch-dest: document' \
	-H 'sec-fetch-mode: navigate' \
	-H 'sec-fetch-site: none' \
	-H 'sec-fetch-user: ?1' \
	-H 'upgrade-insecure-requests: 1' \
	-H 'user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36' \
	-x www.example.com \
	http3-test-inputs/file-test
```

```
../build/h3-header-generator \
	-x www.example.com \
	-p reproxy-test/index.html \
	-H 'dnt: 1' \
	http3-test-inputs/reproxy-test
```
