module.exports = function(RED) {
    "use strict";
    var FitbitClient = require('fitbit-client-oauth2');
    var request = require('request')

    function getOAuth(client_key, client_secret) {
        return new FitbitClient(
            client_key,
            client_secret
        );
    }

    function FitbitNode(n) {
        RED.nodes.createNode(this, n);
        this.username = n.username;
    }

    RED.nodes.registerType("fitbit-credentials", FitbitNode, {
        credentials: {
            username: {type:"text"},
            client_key: {type: "password"},
            client_secret: {type: "password"},
            access_token: {type: "password"},
            refresh_token: {type:"password"},
            expires_at: {type: "password"}
        }
    });

    function FitbitTokenNode(n) {
        RED.nodes.createNode(this, n);

        var credentialNodeId = n.fitbit;
        this.log("node.fitbit " + credentialNodeId);

        var credentials = RED.nodes.getCredentials(credentialNodeId);
        if (credentials && credentials.access_token) {
            var node = this;
            node.status({});
            node.on('input', function(msg) {
                onInput(msg, node, credentialNodeId);
            });
        }
    }
    RED.nodes.registerType("fitbit token", FitbitTokenNode);

    var onInput = function(msg, node, credentialNodeId) {
        var credentials = RED.nodes.getCredentials(credentialNodeId);
        refreshToken(node, credentialNodeId, credentials, function(new_credentials) {
            var access_token = new_credentials.access_token;
            msg.payload = {'access_token': access_token};
            node.log("Access with fitbit token: " + abbreviateToken(access_token));
            node.send(msg);
        });
    }

    var getCallbackUrl = function(req) {
        var protocol = req.protocol;
        if (req.headers['x-forwarded-proto']) {
            protocol = req.headers['x-forwarded-proto'];
        }
        var callback = protocol + "://" + req.get('host') + (RED.settings.httpAdminRoot + '/fitbit-credentials/auth/callback').replace('//', '/');
        return callback;
    }

    var abbreviateToken = function(token) {
        return token.slice(0, 10) + "..." + token.slice(-10);
    }

    var refreshToken = function(node, credentialNodeId, credentials, callback) {
        var now = new Date().getTime();
        node.status({fill:"blue", shape:"dot", text:"fitbit.status.initializing"});

        node.log("Refreshing fitbit token: " + abbreviateToken(credentials.access_token));
        node.log("Used fitbit refresh token: " + abbreviateToken(credentials.refresh_token));

        var oa = getOAuth(credentials.client_key, credentials.client_secret);
        oa.refreshAccessToken(credentials, { forceRefresh: true })
            .then(function(new_token) {
                node.status({fill:"blue", shape:"dot", text:"fitbit.status.authorized"});

                node.log("Refreshed fitbit token: " + abbreviateToken(new_token.token.access_token));

                credentials.access_token = new_token.token.access_token;
                credentials.refresh_token = new_token.token.refresh_token;
                credentials.expires_at = now + 8 * 60 * 60 * 1000;//new_token.token.expires_at.getTime();
                RED.nodes.addCredentials(credentialNodeId, credentials);

                node.log("Saved fitbit credentials: (" + credentialNodeId + ") " + JSON.stringify(credentials))


                node.log("Saved fitbit refresh token: " + abbreviateToken(credentials.refresh_token));

                callback(credentials);

                node.status({});
            }).catch(function(err) {
                node.status({fill:"red", shape:"dot", text:"fitbit.status.failed"});

                node.error('error refreshing fitbit user token: ' + JSON.stringify(err));
                credentials = {};
                RED.nodes.addCredentials(node.id, credentials);
            });
    }

    RED.httpAdmin.get('/fitbit-credentials/:id/auth', function(req, res){
        if (!req.query.client_key || !req.query.client_secret || !req.query.callback) {
            res.sendStatus(400);
            return;
        }

        var credentials = {
            client_key:req.query.client_key,
            client_secret: req.query.client_secret
        };
        RED.nodes.addCredentials(req.params.id, credentials);

        var oa = getOAuth(credentials.client_key, credentials.client_secret);
        var url = oa.getAuthorizationUrl(
            getCallbackUrl(req),
            'activity heartrate location nutrition profile settings sleep social weight',
            req.params.id
        );

        res.redirect(url);
    });

    RED.httpAdmin.get('/fitbit-credentials/auth/callback', function(req, res, next){
        var nodeid = req.query.state;
        var credentials = RED.nodes.getCredentials(nodeid);

        credentials.code = req.query.code;
        var client_key = credentials.client_key;
        var client_secret = credentials.client_secret;
        var oa = getOAuth(client_key, client_secret);

        oa.getToken(credentials.code, getCallbackUrl(req))
            .then(function(token) {
                var options = {
                    uri: "https://api.fitbit.com/1/user/-/profile.json",
                    headers: { "Authorization":"Bearer " + token.token.access_token }
                };

                request.get(options, function(err, httpResponse, body) {
                    if (err) {
                        var resp = RED._("fitbit.error.oautherror", {statusCode: err.statusCode, errorData: err.data});
                        res.send(resp);
                    } else {
                        var result = JSON.parse(body);

                        credentials = {};
                        credentials.username = result.user.displayName;
                        credentials.client_key = client_key;
                        credentials.client_secret = client_secret;
                        credentials.access_token = token.token.access_token;
                        credentials.refresh_token = token.token.refresh_token;
                        credentials.expires_at = new Date().getTime() + 8 * 60 * 60 * 1000;//token.token.expires_at.getTime();

                        RED.nodes.addCredentials(nodeid, credentials);

                        //var node = RED.nodes.getNode(nodeid);
                        //node.log("Saved fitbit credentials: (" + nodeid + ") " + JSON.stringify(credentials))

                        //node.log("Saved fitbit refresh token " + abbreviateToken(credentials.refresh_token));

                        res.send(RED._("fitbit.error.authorized"));
                    }
                });

            }).catch(function(err){
                var resp = RED._("fitbit.error.oautherror", {statusCode: error.statusCode, errorData: error.data});
                res.send(resp);
            });

    });

};
