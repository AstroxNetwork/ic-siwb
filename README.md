
![Sign-In with Bitcoin for the Internet Computer](/media/new_header.png)

A Sign-In with Bitcoin for the Internet Computer.


- [Local Development](#local-development)
- [Frontend Integration and Example](#frontend-integration-and-example)

## Local Development

1. create canister first
 ```bash
dfx canister create ic_siwb_provider  --specified-id be2us-64aaa-aaaaa-qaabq-cai # if you don't have a specified id, it will be created with a random id
 ```

2. deploy
```bash
dfx deploy ic_siwb_provider --argument $'(                                                                                                                                             INT  21:52:52 
    record {
        domain = "127.0.0.1";
        uri = "http://127.0.0.1:5173";
        salt = "123456";
        network = opt "testnet";
        scheme = opt "http";
        statement = opt "Login to the app";
        sign_in_expires_in = opt 1500000000000; 
        session_expires_in = opt 604800000000000; 
        targets = null;
    }
)'
```

Deployment Arguments Explaination: [init_upgrade.rs](https://github.com/AstroxNetwork/ic-siwb/blob/5f763c7af5a209845b35ed28e30e1618f7feae83/packages/ic_siwb_provider/src/service/init_upgrade.rs#L23)



## Frontend Integration and Example

1. ic-siwb-identity
Library: [ic-siwb-identity](https://www.npmjs.com/package/ic-use-siwb-identity)
React Example: [Here](https://github.com/AstroxNetwork/ic-siwb/tree/main/examples/frontend)

2. LaserEyes Connector 
Library: [LaserEyes Connector](https://www.npmjs.com/package/ic-siwb-lasereyes-connector)
React Example: [Here](https://github.com/AstroxNetwork/ic-siwb/tree/main/examples/laserEyes)