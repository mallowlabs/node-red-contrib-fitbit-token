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
        RED.nodes.createNode(this,n);
        this.username = n.username;
    }
    RED.nodes.registerType("fitbit-credentials", FitbitNode,{
        credentials: {
            username: {type:"text"},
            client_key: { type: "password"},
            client_secret: { type: "password"},
            access_token: {type: "password"},
            refresh_token: {type:"password"},
            expires_at: {type: "number"}
        }
    });

    function FitbitInNode(n) {
        RED.nodes.createNode(this, n);

        this.fitbitConfig = RED.nodes.getNode(n.fitbit);
        if (!this.fitbitConfig) {
            this.warn(RED._("fitbit.warn.missing-credentials"));
            return;
        }

        var credentials = this.fitbitConfig.credentials;
        if (credentials && credentials.access_token) {
            var node = this;
            node.on('input', function(msg) {
                var credentials = node.fitbitConfig.credentials;
                refreshToken(node, credentials);

                var access_token = credentials.access_token;
                msg.payload = {'access_token': access_token};
                node.send(msg);
            });
            node.on('refresh', function(msg) {
                var credentials = node.fitbitConfig.credentials;
                refreshToken(node, credentials);
            });
            var interval = setInterval(function() {
                node.emit("refresh", {});
            }, 4 * 60 * 60 * 1000); // 4 hours
            node.on("close", function() {
                if (interval !== null) { clearInterval(interval); }
            });
        }
    }
    RED.nodes.registerType("fitbit token", FitbitInNode);

    var getCallbackUrl = function(req) {
        var protocol = req.protocol;
        if (req.headers['x-forwarded-proto']) {
            protocol = req.headers['x-forwarded-proto'];
        }
        var callback = protocol + "://" + req.get('host') + (RED.settings.httpAdminRoot + '/fitbit-credentials/auth/callback').replace('//', '/');
        return callback;
    }

    var refreshToken = function(node, credentials) {
        node.status({fill:"blue", shape:"dot", text:"fitbit.status.initializing"});
        var now = new Date().getTime();

        if (now >= credentials.expires_at) {
            var oa = getOAuth(credentials.client_key, credentials.client_secret);
            oa.refreshAccessToken(credentials)
                .then(function(new_token) {
                    node.status({fill:"blue", shape:"dot", text:"fitbit.status.authorized"});

                    credentials.access_token = new_token.token.access_token;
                    credentials.refresh_token = new_token.token.refresh_token;
                    credentials.expires_at = now + 8 * 60 * 60 * 1000;//new_token.token.expires_at.getTime();
                    RED.nodes.addCredentials(node.id, credentials);
                }).catch(function(err) {
                    node.status({fill:"red", shape:"dot", text:"fitbit.status.failed"});

                    console.log('error refreshing user token', err);
                    credentials = {};
                    RED.nodes.addCredentials(node.id, credentials);
                });
        }
        node.status({});
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
                        credentials.expires_at = new Date().getTime() + token.token.expires_in * 1000;//token.token.expires_at.getTime();

                        RED.nodes.addCredentials(nodeid, credentials);
                        res.send(RED._("fitbit.error.authorized"));
                    }
                });

            }).catch(function(err){
                var resp = RED._("fitbit.error.oautherror", {statusCode: error.statusCode, errorData: error.data});
                res.send(resp);
            });

    });

};
