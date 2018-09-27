node-red-contrib-fitbit-token
====================

[Node-RED](http://nodered.org) nodes that gets an access token from [Fitbit](https://www.fitbit.com).
This node supports OAuth2.

Install
-------

Run the following command in the root directory of your Node-RED install

<!--
        npm install node-red-contrib-fitbit-token
-->

    $ git clone https://github.com/mallowlabs/node-red-contrib-fitbit-token.git
    $ cd node-red-contrib-fitbit-token
    $ npm link

Usage
-----

Get an access token of [Fitbit](https://www.fitbit.com) API.
You can get Fitbit API access token in `msg.payload.access_token`.

Specify the callback URL:

```
http(s)://YOUR_NODERED_HOST/fitbit-credentials/auth/callback
```

Credits
-----
This project is forked form [node-red/node-red-web-nodes](https://github.com/node-red/node-red-web-nodes/blob/master/fitbit/) (Apache License Version 2.0 by IBM).
