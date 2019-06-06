# aws-ddns
Anonymous, Dynamic DNS using AWS Lamdba (NodeJS).

#### Concept based on the following related works
https://medium.com/aws-activate-startup-blog/building-a-serverless-dynamic-dns-system-with-aws-a32256f0a1d8
https://medium.com/@jmathai/create-a-serverless-dynamic-dns-system-with-aws-lambda-fab5d0d02297

## Why?
Provide an anonymous dynamic DNS service using AWS Lambda. Implementation is entirely NodeJS with minimal dependencies (only AWS, crypto, dns). Calling this Lambda, a user can claim a cname alias to the route53 domain which points to the user's IP address. See usage below.

## Example Usage
### Creating public/private keypairs
```sh
openssl genrsa -out myPrivateKey.pem 4096
openssl rsa -in myPrivateKey.pem -out myPublicKey.pem -outform PEM -pubout
```
### Claim an alias
#### Request to claim alias 'test'
```sh
curl -X POST \
  https://myroute53domain.com \
	-H 'Content-Type: application/json' \
	-d '{"alias": "test","publicKey": "'"$(cat  myPublicKey.pem)"'"}'
```
#### Response
```json
{
    "ok": true,
    "data": {
        "alias": "test",
        "cname": "test.myroute53domain.com",
        "ip": "XXX.XXX.XXX.XXX",
        "secret": "d34db33fd34db33fd34db33fd34db33f"
    }
}
```
### Update a claimed alias
#### Request alias 'test'
```sh
curl -X POST \
  https://myroute53domain.com \
	-H 'Content-Type: application/json' \
	-d '{"alias": "test","signature": "'"$(echo -n '{"alias":"test","now":"'"$(date +%s000)"'","secret":"d34db33fd34db33fd34db33fd34db33f"}' | openssl dgst -sha256 -sign myPrivateKey.pem -binary | base64)"'"}'
```
#### Response
```json
{
	"ok":true,
	"data":{
		"alias":"test",
		"cname":"test.myroute53domain.com",
		"ip":"XXX.XXX.XXX.XXX"
	}
}
```
### Look up an alias
#### Request alias 'test'
```sh
curl -X GET 'https://myroute53domain.com?alias=test'
```
#### Response
```json
{
	"ok":true,
	"data":{
		"address":"XXX.XXX.XXX.XXX",
		"family":4,
		"alias":"test",
		"cname":"test.myroute53domain.com",
		"created":"Mon Jan 01 2019 00:00:00 GMT+0000 (UTC)",
		"updated":"Mon Jan 01 2019 00:00:00 GMT+0000 (UTC)"
	}
}
```
