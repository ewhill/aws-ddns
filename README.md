# aws-ddns
Anonymous, Dynamic DNS using AWS Lamdba (NodeJS).

#### Concept based on the following related works
https://medium.com/aws-activate-startup-blog/building-a-serverless-dynamic-dns-system-with-aws-a32256f0a1d8
https://medium.com/@jmathai/create-a-serverless-dynamic-dns-system-with-aws-lambda-fab5d0d02297

## Why?
Provide an anonymous dynamic DNS service using AWS Lambda. Implementation is entirely NodeJS with minimal dependencies (only AWS, crypto, dns). Calling this Lambda, a user can claim a cname alias to the route53 domain which points to the user's IP address.

## Features
- **Compatible**
	- API can be called from clients using simple combination of Curl and OpenSSL, so as to provide easy integtation with a multitude of systems and architectures. See 'Example Usage' below.
- **Serverless**
	- Ran completely in AWS Lambda; only fractions of the cost when compared to traditional infrastructure stacks.
- **Anonymous**
	- Records can be claimed by providing a valid RSA public key and updated using only the corresponding RSA private key to generate a cryptographic signature proving ownership.
- **Secure**
	- **Cryptographic proof-of-ownership**
	- **No secrets over-the-wire**
		- When a record is claimed, it is done so by providing a valid RSA public key (which the API uses to validate cryptographic ownership of the record upon update). When a client wishes to update a record, it sends only a computed signature to the API which, while this signature is computed from sensitive information (API secret, client UTC timestamp, and client private key), does not reveal said information in any way given the one-way cryptographic nature of generation.
	- **Impossible to replay requests**
		- When a client wishes to update an owned record, a UTC timestamp is added to the update payload. The signature is then generated from this payload and sent to the API. The API then checks the signature against a set of signatures generated from a predefined interval of seconds (prior and future) based off of the API's current time. The record in question will only be updated if a matching signature is found in the set of generated signatures by the API. The API waits until the API's current time past the future portion of the interval before returning a result to the client. In this way, replay attacks are not possible.

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
OR
```sh
nslookup test.myroute53domain.com
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
OR
```
Non-authoritative answer:
Name:	test.myroute53domain.com
Address: XXX.XXX.XXX.XXX
```
