'use strict';

const dns = require('dns');
const crypto = require('crypto');
const AWS = require('aws-sdk');

var route53 = new AWS.Route53();
var dynamodb = new AWS.DynamoDB();

// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
// !!!!!!!!!! Be sure to set these necessary environment variables !!!!!!!!!!!!!
// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
const DYNAMO_TABLE_NAME = process.env["DYNAMO_TABLE_NAME"];
const ROUTE53_HOSTED_ZONE_ID = process.env["ROUTE53_HOSTED_ZONE_ID"];
const ROUTE53_DOMAIN_NAME = process.env["ROUTE53_DOMAIN_NAME"];
// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

// -----------------------------------------------------------------------------
const REQUEST_METHOD_GET = 0;
const REQUEST_METHOD_POST = 1;
// -----------------------------------------------------------------------------

const generateSecret = (length) => {
  if(!length || typeof length !== "number") {
    throw new Error("generateSecret: Invalid parameter `length`.");
  }
  
  // Ensure length is a multiple of 2
  if((length % 2) !== 0) {
    throw new Error("Length must be divisible by two!");
  }
  
  // Use crypto to generate (length/2) random bytes and then convert them to hex
  return crypto.randomBytes(parseInt(Math.floor(length/2))).toString('hex');
};

const lookupAlias = (alias) => {
  return new Promise((resolve, reject) => {
    if(!alias || typeof alias !== "string" || alias.length < 1) {
      return reject(new Error("lookupAlias: Invalid parameter `alias`."));
    }
    
    // Set up the query...
    var params = {
      Key: {
        "alias": {
          S: alias
        },
      },
      TableName: DYNAMO_TABLE_NAME
    };

    // Perform the query...
    dynamodb.getItem(params, function(err, data) {
      if(err) {
        console.error(err, err.stack);
        return reject(err);
      } else {
        return resolve(data.Item);
      }
    });
  });
};

const updateAlias = (alias) => {
  return new Promise((resolve, reject) => {
    if(!alias || typeof alias !== "string" || alias.length < 1) {
      return reject(new Error("updateAlias: Invalid parameter `alias`."));
    }
    
    // Static time in MS...
    var now = Date.now().toString();
    
    // Set up the update...
    var params = {
      ExpressionAttributeNames: {
        "#U": "updated"
      }, 
      ExpressionAttributeValues: {
        ":u": {
          N: now
        }
      }, 
      Key: {
        "alias": {
          S: alias
        }
      }, 
      ReturnValues: "ALL_NEW", 
      TableName: DYNAMO_TABLE_NAME,
      UpdateExpression: "SET #U = :u"
    };
  
    // Perform the update...
    dynamodb.updateItem(params, function(err, data) {
      if(err) {
        console.error(err, err.stack);
        return reject(err);
      } else {
        return resolve(data);
      }
    });
  });
};

const insertAlias = (alias, publicKey) => {
  return new Promise((resolve, reject) => {
    if(!alias || typeof alias !== "string" || alias.length < 1) {
      return reject(new Error("insertAlias: Invalid parameter `alias`."));
    }
    
    if(!publicKey || typeof publicKey !== "string" || publicKey.length < 1) {
      return reject(new Error("insertAlias: Invalid parameter `publicKey`."));
    }
    
    // We will need the current time in MS to be static...
    var now = Date.now().toString();
    
    // Generate a random secret string (hex, 32chars long) to be used in the 
    // signature generation by the client in order to provide an added level of 
    // security
    var secret = generateSecret(32);
  
    // Set up the insertion...
    var params = {
      Item: {
        "alias": {
          S: alias
        },
        "publicKey": {
          S: publicKey
        },
        "secret": {
          S: secret
        },
        "created": {
          N: now
        },
        "updated": {
          N: now
        }
      },
      TableName: DYNAMO_TABLE_NAME
    };
    
    // Perform the insertion...
    dynamodb.putItem(params, function(err, data) {
      if(err) {
        console.error(err, err.stack);
        return reject(err);
      } else {
        return resolve({
          alias,
          secret,
        });
      }
    });
  });
};

const validatePublicKey = (publicKey) => {
  return new Promise((resolve, reject) => {
    // Ensure `publicKey` is actually set first...
    if(!publicKey || typeof publicKey !== "string" || publicKey.length < 1) {
      return reject(new Error("Invalid parameter `publicKey`!"));
    }
    
    // To test for a valid public key, simply try to encrypt some random data 
    // with the given `publicKey`.  
    try {
      crypto.publicEncrypt(new Buffer(publicKey, 'ascii'), 
        crypto.randomBytes(100));
      
      // If we reach this code block, we could successfully use crypto lib to 
      // encrypt the random data with the given `publicKey`, so it must be 
      // valid, resolve true
      return resolve(true);
    } catch(e) {
      // Something went wrong (probably not a valid RSA public key), gracefully 
      // reject
      return resolve(false);
    }
  });
};

const verifySignature = (data, publicKey, signature) => {
  return new Promise((resolve, reject) => {
    if(!data || typeof data !== "object") {
      return reject(new Error("verifySignature: Invalid parameter `data`."));
    }
    
    if(!data.hasOwnProperty("alias") || typeof data.alias !== "string" || 
      data.alias.length < 1) {
        return reject(
          new Error("verifySignature: Invalid parameter `data.alias`."));
    }
    
    if(!data.hasOwnProperty("secret") || typeof data.secret !== "string" || 
      data.secret.length < 1) {
        return reject(
          new Error("verifySignature: Invalid parameter `data.secret`."));
    }
    
    if(!publicKey || typeof publicKey !== "string" || publicKey.length < 1) {
        return reject(
          new Error("verifySignature: Invalid parameter `publicKey`."));
    }
    
    if(!signature || typeof signature !== "string" || signature.length < 1) {
        return reject(
          new Error("verifySignature: Invalid parameter `signature`."));
    }
    
    let now = new Date(Date.now());
    now.setMilliseconds(0);

    // Use a span of +/- 10s ([now-10s, now+10s])
    let span = 10;

    let waitForIntervalFutureBound = ((now, span) => {
      return (callback) => {
        let endTime = now.getTime() + (span * 1000);
        let waitTime = endTime - Date.now();
        
        if(waitTime > 0) 
          setTimeout(callback, waitTime);
        else 
          callback();
      };
    })(now, span);
      
    
    try {
      // Set up some variables...
      let publicKeyBuf = new Buffer(publicKey, 'ascii');
      let signatureBuf = new Buffer(signature, 'base64');
      
      // Cycle through our span...
      for(let i=0; i<=span; i++) {
        // Next 'for' handles the +/-
        for(let j=0; j<2; j++) {
          // Create a signature verifier from crypto lib
          let verifier = crypto.createVerify('RSA-SHA256');
          
          // Do the +/-...
          let testDate = new Date(j === 0 ? 
            (now.getTime() - i*1000) : 
            (now.getTime() + i*1000));
          
          // Throw away milliseconds (for simplicity)...
          testDate.setMilliseconds(0);
          
          // Update the digest to produce the signature
          verifier.update(JSON.stringify({
            'alias': data.alias,
            'now': testDate.getTime().toString(),
            'secret': data.secret
          }), 'ascii');
          
          // Check if the generated signature matches the one given
          if(verifier.verify(publicKeyBuf, signatureBuf)) {
            // A match means we have cryptographically proven ownership, 
            // resolve true
            return waitForIntervalFutureBound(() => resolve(true));
          }
        }
      }
      
      // We reach this code block if there was no match and we therefore cannot 
      // prove cryptographic ownership of the message or update request
      throw new Error(`Invalid signature! Server local time ` +
        `is ${(new Date(Date.now())).toString()}.`);
    } catch(e) {
      // There was some other error, gracefully reject
      return waitForIntervalFutureBound(() => reject(e));
    }
  });
};

const updateIp = (alias, ip) => {
  return new Promise((resolve, reject) => {
    // Perform the Route53 upsert...
    route53.changeResourceRecordSets({
      HostedZoneId: ROUTE53_HOSTED_ZONE_ID,
      ChangeBatch: {
        Changes: [{
          Action: 'UPSERT',
          ResourceRecordSet: {
            Name: `${alias}.${ROUTE53_DOMAIN_NAME}`,
            Type: 'A',
            ResourceRecords: [{
              Value: ip
            }],
            TTL: 300
          }
        }],
        Comment: 'ddns update'
      }
    }, function (err, data) {
      if(err) return reject(err);
      return resolve(data);
    });
  });
};

const getIp = (cname) => {
  return new Promise((resolve, reject) => {
    // Perform a simple DNS lookup query (nslookup), return the results
    dns.lookup(cname, (err, address, family) => {
      if(err) {
        if(err.code === "ENOTFOUND") {
          return reject(new Error("No such alias."));
        } else {
          return reject(err);
        }
      }
      
      return resolve({ address, family });
    });
  });
};

const formatDate = (ts) => {
  // If `ts` is a string, parse it to an int
  if(typeof ts === "string") {
    ts = parseInt(ts);
  }
  
  // Convert `ts` to a JS Date object and return it as a formatted string.
  let d = new Date(ts);
  return d.toString();
};

const checkAlias = (alias) => {
  return new Promise((resolve, reject) => {
    if(!alias || typeof alias !== "string" || alias.length < 1) {
      return reject(new Error("Missing or incorrect parameter `alias`!"));
    } else if(alias && typeof alias === "string" && alias.length >= 1) {
      if(alias.length < 4) {
        return reject(new Error("Parameter `alias` must be at least 4 " + 
          "characters in length!"));
      } else if(!/^([a-z0-9][a-z0-9_-]*[a-z0-9])$/ig.test(alias)) {
        return reject(new Error("Invalid `alias` format; only letters, " + 
          "numbers, underscores, and dashes are permitted and the alias " + 
          "must not begin or end with an underscore or a dash."));
      }
    } else {
      // Fail-safe
      return reject(new Error("Parameter `alias` is not valid."));
    }
    
    return resolve();
  });
};

const getParams = (event) => {
  return new Promise((resolve, reject) => {
    // Set variables to POST data parameters (if possible)
    let publicKey = (event.body ? event.body.publicKey : null);
    let alias =  (event.body ? event.body.alias : null);
    let signature = (event.body ? event.body.signature : null);
    let requestMethod = null;
    
    // Fall back to query parameters (if possible)
    if(!alias) {
      try {
        alias = event.params.querystring.alias;
      } catch(e) {
        alias=null;
      }
    }

    if(!publicKey) {
      try {
        publicKey = event.params.querystring.publicKey;
      } catch(e) {
        publicKey=null;
      }
    }

    if(!signature) {
      try {
        signature = event.params.querystring.signature;
      } catch(e) {
        signature=null;
      }
    }
  
    // Make sure we have the correct parameters for the given `http-method`...
    if((event.context["http-method"].toUpperCase() === "POST")) {
      requestMethod = REQUEST_METHOD_POST;
      
      var hasPublicKey = (publicKey && typeof publicKey == "string" && 
        publicKey.length > 0);
      var hasSignature = (signature && typeof signature == "string" && 
        signature.length > 0);
      
      if(!hasPublicKey && !hasSignature) {
          return reject(new Error("To set (claim) a record, you must " + 
            "provide a valid RSA public key or to update an already-claimed " + 
            "record, you must provide a valid cryptographic signature."));
      }
    } else if((event.context["http-method"].toUpperCase() === "GET")) {
      requestMethod = REQUEST_METHOD_GET;
      
      if((!alias || typeof alias !== "string" || alias.length < 1)) {
        return reject(
          new Error("To query for a record, you must provide a valid alias."));
      }
    }
    
    return resolve({ alias, publicKey, signature, requestMethod });
  });
};

/******************************************************************************/
/******************************************************************************/
/******************************************************************************/
/******************************************************************************/

exports.handler = (event, context) => {
  let alias = null, 
    publicKey = null, 
    signature = null,
    requestMethod = null;
  
  return getParams(event)
    .then(data => {
      alias = data.alias;
      publicKey = data.publicKey;
      signature = data.signature;
      requestMethod = data.requestMethod;
      
      return Promise.resolve();
    })
    .then(result => checkAlias(alias)) // Check the given `alias` format
    .then(result => lookupAlias(alias)) //  Retrieve DynamoDB record for `alias`
    .then(lookupData => {
      /*
        If the request method is GET, then we perform a nslookup on the given 
        `alias` and return the record last set by the client or user.
        
        If the request method is POST, then we are going to try and set or 
        update record associated with the given `alias`.
      */
      if(requestMethod === REQUEST_METHOD_GET) {
        // Perform 'nslookup' on the alias and return the lookup data
        return getIp(`${alias}.${ROUTE53_DOMAIN_NAME}`)
          .then(ipData => {
            // Return DynamoDB record combined with the nslookup data.
            return {
              'address': ipData.address,
              'family': ipData.family,
              'alias': lookupData.alias.S,
              'cname': `${alias}.${ROUTE53_DOMAIN_NAME}`,
              'publicKey': lookupData.publicKey.S,
              'created': formatDate(lookupData.created.N),
              'updated': formatDate(lookupData.updated.N)
            };
         });
      } else if(requestMethod === REQUEST_METHOD_POST) {
        // Check if the alias lookup succeeded (record exists, is claimed).
        if(!lookupData || !lookupData.hasOwnProperty('publicKey') || 
          lookupData.publicKey.S.length <1) {
            // Are we given a valid publicKey?
            if(publicKey && publicKey.length > 0) {
              // We want to set (claim) a DDNS record for the first time, 
              // providing a RSA public key as future proof of ownership.
              return validatePublicKey(publicKey)
                .then(result => {
                  // Claim the record to belong to the given RSA public key by 
                  // inserting the alias and associated properties into 
                  // DynamoDB.
                  return insertAlias(alias, publicKey);
                })
                .then(result => {
                  // Update the alias's Route53 CNAME ip address.
                  return updateIp(alias, event.context.sourceIp)
                    .then(data => {
                      // Return the updated information.
                      return {
                        'alias': alias,
                        'cname': `${alias}.${ROUTE53_DOMAIN_NAME}`,
                        'ip': `${event.context.sourceIp}`,
                        'secret': result.secret
                      };
                    });
                });
            } else {
              // No valid public key given
              if(signature) { // ... but we were given a signature instead
                throw new Error("Record is not claimed. To claim a record, " + 
                  "please provide a valid RSA public key in place of the " + 
                  "`signature` parameter.");
              } else { // ... and no signature given either
                throw new Error("Creating (claiming) a record requires a " + 
                  "valid RSA public key, yet no `publicKey` parameter was " + 
                  "given!");
              }
            }
        } else if(lookupData && lookupData.hasOwnProperty('publicKey') && 
          lookupData.publicKey.S.length > 0 && 
          lookupData.hasOwnProperty("secret") && 
          lookupData.secret.S.length > 0) {
            // Are we given a valid signature?
            if(signature && signature.length > 0) {
              // We want to update a DDNS record, providing a 
              // private-key-encrypted signature of the message which proves 
              // ownership of the record.
              return verifySignature(
                  {
                    'alias': alias,
                    'secret': lookupData.secret.S
                  },
                  lookupData.publicKey.S,
                  signature
                )
                .then(result => {
                  // Update the alias's `updated` timestamp DynamoDB
                  return updateAlias(alias);
                })
                .then(data => {
                  // Update the alias's Route53 CNAME entry
                  return updateIp(alias, event.context.sourceIp)
                    .then(data => {
                      return {
                        'alias': alias,
                        'cname': `${alias}.${ROUTE53_DOMAIN_NAME}`,
                        'ip': `${event.context.sourceIp}`
                      };
                    });
                });
            } else {
              // No signature given
              if(publicKey) { // ... but we were given a `publicKey`
                throw new Error("Record already claimed. To update a record, " +
                  "please provide a valid cryptographic signature in place " + 
                  "of the `publicKey` parameter.");
              } else { // ... and no `publicKey` was given
                throw new Error("Updating a record requires a valid " + 
                  "cryptographic signature, yet no `signature` param was " + 
                  "given!");
              }
            }
        }
      }
    })
    .then(result => {
      // This is always executed on success and returns the data to the user
      return {
        ok: true,
        data: result
      };
    })
    .catch(err => {
      // This is always executed on failure and returns the error to the user
      return {
        ok: false,
        data: err.message
      };
    });
};
